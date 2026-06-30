package com.example.demo.protocol.core;

import com.example.demo.protocol.annotation.Payload;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.Packet;

import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.util.*;

public final class ProtocolCodec<T> {

    private final Class<T> clazz;
    private final List<FieldInfo> fixedFields; // 按 order 排序
    private final FieldInfo payloadField;      // @Payload 字段(向后兼容)

    public ProtocolCodec(Class<T> clazz) {
        this.clazz = clazz;
        List<FieldInfo> fixed = new ArrayList<>();
        FieldInfo payload = null;

        for (Field f : clazz.getDeclaredFields()) {
            if (f.isAnnotationPresent(Payload.class)) {
                payload = FieldInfo.forPayload(f);
            } else if (f.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolField.class)) {
                fixed.add(new FieldInfo(f));
            }
        }
        fixed.sort(Comparator.comparingInt(f -> f.order));
        validateReferences(fixed);
        this.fixedFields = fixed;
        this.payloadField = payload;
    }

    /** 注册期校验:lengthField 引用的字段必须存在,且 order 必须更小(禁止前向引用)。 */
    private static void validateReferences(List<FieldInfo> sortedFields) {
        Map<String, Integer> nameToOrder = new HashMap<>();
        for (FieldInfo fi : sortedFields) {
            nameToOrder.put(fi.name, fi.order);
        }
        for (FieldInfo fi : sortedFields) {
            // lengthField 校验
            if (!fi.lengthField.isEmpty()) {
                Integer refOrder = nameToOrder.get(fi.lengthField);
                if (refOrder == null) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "' lengthField references unknown field '" + fi.lengthField + "'");
                }
                if (refOrder >= fi.order) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "' lengthField references '" + fi.lengthField
                                    + "' which is not earlier in order (forward ref forbidden)");
                }
            }
            // presentIf 校验(只查字段存在)
            if (!fi.presentIf.isBlank()) {
                int eq = fi.presentIf.indexOf("==");
                String left = eq >= 0 ? fi.presentIf.substring(0, eq).trim() : fi.presentIf.trim();
                if (!nameToOrder.containsKey(left)) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "' presentIf references unknown field '" + left + "'");
                }
            }
        }
    }

    public T deserialize(byte[] rawData) {
        return deserialize(rawData, 0, rawData.length);
    }

    @SuppressWarnings("unchecked")
    public T deserialize(byte[] rawData, int offset, int length) {
        try {
            T obj = clazz.getDeclaredConstructor().newInstance();
            FieldContext.Impl ctx = (FieldContext.Impl) FieldContext.create(obj);
            BitCursor cursor = new BitCursor(rawData, offset);

            for (FieldInfo fi : fixedFields) {
                if (!evalPresentIf(fi.presentIf, ctx)) {
                    continue; // 条件不满足:不读字节、不入 ctx
                }
                long size = resolveSize(fi, obj, ctx, true);
                Object value = readValue(fi, cursor, (int) size, ctx);
                fi.field.setAccessible(true);
                fi.field.set(obj, value);
                ctx.put(fi.name, value);
            }

            // 向后兼容:@Payload 取剩余字节
            if (payloadField != null) {
                int consumedBits = cursor.bitOffset();
                int consumedBytes = (consumedBits + 7) / 8;
                if (length > consumedBytes) {
                    payloadField.field.setAccessible(true);
                    payloadField.field.set(obj, Arrays.copyOfRange(rawData, offset + consumedBytes, offset + length));
                }
            }
            return obj;
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize " + clazz.getName(), e);
        }
    }

    public byte[] serialize(T obj) {
        try {
            FieldContext.Impl ctx = (FieldContext.Impl) FieldContext.create(obj);
            // 先把所有字段值装入 ctx(序列化时 ctx 一次性完整)
            for (FieldInfo fi : fixedFields) {
                fi.field.setAccessible(true);
                ctx.put(fi.name, fi.field.get(obj));
            }

            // 第一遍:算总位数
            int totalBits = 0;
            for (FieldInfo fi : fixedFields) {
                if (!evalPresentIf(fi.presentIf, ctx)) {
                    continue;
                }
                long size = resolveSize(fi, obj, ctx, false);
                if (size < 0) {
                    throw new IllegalStateException("cannot resolve size of field " + fi.name);
                }
                totalBits += size;
            }
            byte[] payloadData = null;
            if (payloadField != null) {
                payloadField.field.setAccessible(true);
                payloadData = (byte[]) payloadField.field.get(obj);
                if (payloadData != null) {
                    totalBits += payloadData.length * 8;
                }
            }

            BitCursor cursor = new BitCursor((totalBits + 7) / 8);
            for (FieldInfo fi : fixedFields) {
                if (!evalPresentIf(fi.presentIf, ctx)) {
                    continue;
                }
                long size = resolveSize(fi, obj, ctx, false);
                writeValue(fi, obj, cursor, (int) size, ctx);
            }
            if (payloadField != null && payloadData != null) {
                cursor.writeBytes(payloadData);
            }
            return cursor.bytes();
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize " + clazz.getName(), e);
        }
    }

    /** 求值 presentIf 表达式 "field==value",支持十进制/十六进制(0x..) 字面量。 */
    private static boolean evalPresentIf(String expr, FieldContext ctx) {
        if (expr == null || expr.isBlank()) {
            return true;
        }
        int eq = expr.indexOf("==");
        if (eq < 0) {
            throw new IllegalArgumentException("presentIf must be 'field==value': " + expr);
        }
        String left = expr.substring(0, eq).trim();
        String right = expr.substring(eq + 2).trim();
        long expected = right.toLowerCase().startsWith("0x")
                ? Long.parseLong(right.substring(2), 16)
                : Long.parseLong(right);
        return ctx.getInt(left) == expected;
    }

    // ---- 动态尺寸解析(Task 6/7 扩充 lengthField/presentIf) ----
    private long resolveSize(FieldInfo fi, Object obj, FieldContext ctx, boolean deserialize) throws Exception {
        // 1. 钩子优先
        if (obj instanceof DynamicSize ds) {
            long s = ds.computeSize(fi.name, ctx);
            if (s >= 0) {
                return s;
            }
        }
        // 2. 声明式 lengthField(Task 6 启用)
        if (!fi.lengthField.isEmpty() && ctx.hasRead(fi.lengthField)) {
            int ref = ctx.getInt(fi.lengthField);
            return fi.lengthUnit == LengthUnit.BYTES ? ref * 8L : ref;
        }
        // 3. NESTED:按嵌套实体自身固定字段位数计算(取整到整字节)
        //    BitCursor 的 readBytes/writeBytes 要求整字节 & 字节对齐,故 NESTED 按
        //    「嵌套实体 serialize 后的字节长度 * 8」计位。Phase 1 仅支持嵌套实体本身
        //    全为固定 size 字段的情形(任一嵌套字段无确定 size → 抛异常,留待后续)。
        if (effectiveType(fi) == FieldType.NESTED) {
            long raw = fixedBitSize(fi.field.getType());
            return ((raw + 7) / 8) * 8;
        }
        // 4. 固定 size
        if (fi.size > 0) {
            return fi.size;
        }
        throw new IllegalStateException("cannot resolve size of field " + fi.name);
    }

    /**
     * 计算某实体类型「全固定字段」的位总和(供 NESTED 定长解析)。
     * 任一 {@code @ProtocolField} 字段无确定 size(≤0)即抛异常——这意味着
     * NESTED-in-middle 且变长的情形在 Phase 1 不支持(可接受)。
     */
    private static long fixedBitSize(Class<?> type) {
        long sum = 0;
        for (Field f : type.getDeclaredFields()) {
            if (f.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolField.class)) {
                com.example.demo.protocol.annotation.ProtocolField ann =
                        f.getAnnotation(com.example.demo.protocol.annotation.ProtocolField.class);
                if (ann.size() <= 0) {
                    throw new IllegalStateException(
                            "cannot resolve fixed size of nested field " + f.getName()
                                    + " in " + type.getName()
                                    + ": dynamic nested length unsupported in Phase 1");
                }
                sum += ann.size();
            }
        }
        return sum;
    }

    private Object readValue(FieldInfo fi, BitCursor cursor, int size, FieldContext ctx) throws Exception {
        FieldType type = effectiveType(fi);
        return switch (type) {
            case INT, UNSIGNED -> convertToFieldType(fi.field.getType(), cursor.readBits(size), type == FieldType.UNSIGNED);
            case BYTES -> cursor.readBytes(size);
            case STRING -> new String(cursor.readBytes(size), Charset.forName(fi.charset));
            case NESTED -> {
                ProtocolCodec<?> nested = codecFor(fi.field.getType());
                byte[] seg = cursor.readBytes(size);
                yield nested.deserialize(seg, 0, seg.length);
            }
        };
    }

    private void writeValue(FieldInfo fi, Object obj, BitCursor cursor, int size, FieldContext ctx) throws Exception {
        FieldType type = effectiveType(fi);
        fi.field.setAccessible(true);
        Object value = fi.field.get(obj);
        switch (type) {
            case INT, UNSIGNED -> {
                long v = convertFromFieldType(value);
                cursor.writeBits(v, size);
            }
            case BYTES -> cursor.writeBytes((byte[]) value);
            case STRING -> cursor.writeBytes(((String) value).getBytes(Charset.forName(fi.charset)));
            case NESTED -> {
                ProtocolCodec<?> nested = codecFor(fi.field.getType());
                cursor.writeBytes(serializeNested(nested, value));
            }
        }
    }

    private FieldType effectiveType(FieldInfo fi) {
        if (fi.type != FieldType.INT) {
            return fi.type; // 显式指定
        }
        // INT 默认:按 Java 类型推断(BYTES/STRING/NESTED)
        Class<?> t = fi.field.getType();
        if (t == byte[].class) {
            return FieldType.BYTES;
        }
        if (t == String.class) {
            return FieldType.STRING;
        }
        // 字段类型本身是 @ProtocolPacket 实体 → 当作 NESTED(也可显式 type=NESTED)
        if (!t.isPrimitive() && !Number.class.isAssignableFrom(t)
                && t.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolPacket.class)) {
            return FieldType.NESTED;
        }
        return FieldType.INT;
    }

    @SuppressWarnings("rawtypes")
    private static final Map<Class<?>, ProtocolCodec> NESTED_CACHE = new HashMap<>();

    @SuppressWarnings("unchecked")
    private ProtocolCodec<?> codecFor(Class<?> type) {
        ProtocolCodec<?> cached = NESTED_CACHE.get(type);
        if (cached != null) {
            return cached;
        }
        ProtocolCodec<?> c = new ProtocolCodec<>(type);
        NESTED_CACHE.put(type, c);
        return c;
    }

    /**
     * 序列化嵌套实体。{@code ProtocolCodec<?>} 的 T 是通配符捕获,无法直接接受 Object,
     * 故以 raw 类型绕过泛型(嵌套实体的类型已由字段声明保证一致)。
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static byte[] serializeNested(ProtocolCodec<?> codec, Object value) {
        return ((ProtocolCodec) codec).serialize(value);
    }

    private static Object convertToFieldType(Class<?> type, long val, boolean unsigned) {
        if (unsigned) {
            if (type == int.class || type == Integer.class) return (int) val;
            if (type == long.class || type == Long.class) return val;
        }
        if (type == byte.class || type == Byte.class) return (byte) val;
        if (type == short.class || type == Short.class) return (short) val;
        if (type == int.class || type == Integer.class) return (int) val;
        if (type == long.class || type == Long.class) return val;
        return val;
    }

    private static long convertFromFieldType(Object value) {
        if (value == null) {
            return 0;
        }
        if (value instanceof Number n) {
            return n.longValue();
        }
        return 0;
    }

    // ---- pcap4j 适配(保留旧接口) ----
    public Packet toPacket(byte[] rawData, int offset, int length) {
        org.pcap4j.util.ByteArrays.validateBounds(rawData, offset, length);
        T obj = deserialize(rawData, offset, length);
        return new AutoPacket(rawData, offset, length, obj);
    }

    public Packet toPacket(T obj) {
        byte[] rawData = serialize(obj);
        return new AutoPacket(rawData, 0, rawData.length, obj);
    }

    public T fromPacket(Packet packet) {
        return deserialize(packet.getRawData());
    }

    // ---- 内部结构 ----
    private static final class FieldInfo {
        final Field field;
        final String name;
        final int order;
        final int size;
        final FieldType type;
        final String lengthField;
        final LengthUnit lengthUnit;
        final String presentIf;
        final String charset;

        /** 常规字段构造:读取 @ProtocolField 的全部属性。 */
        FieldInfo(Field f) {
            this.field = f;
            this.name = f.getName();
            com.example.demo.protocol.annotation.ProtocolField ann = f.getAnnotation(com.example.demo.protocol.annotation.ProtocolField.class);
            this.order = ann.order();
            this.size = ann.size();
            this.type = ann.type();
            this.lengthField = ann.lengthField();
            this.lengthUnit = ann.lengthUnit();
            this.presentIf = ann.presentIf();
            this.charset = ann.charset();
        }

        /** @Payload 字段构造:无 @ProtocolField,仅需字段引用(其余属性用占位值)。 */
        static FieldInfo forPayload(Field f) {
            return new FieldInfo(f, f.getName());
        }

        private FieldInfo(Field f, String name) {
            this.field = f;
            this.name = name;
            this.order = -1;
            this.size = -1;
            this.type = FieldType.BYTES;
            this.lengthField = "";
            this.lengthUnit = LengthUnit.BYTES;
            this.presentIf = "";
            this.charset = "UTF-8";
        }
    }

    private final class AutoPacket extends AbstractPacket {
        private static final long serialVersionUID = 1L;
        private final byte[] rawData;
        private final AutoHeader autoHeader;

        AutoPacket(byte[] rawData, int offset, int length, T obj) {
            this.rawData = Arrays.copyOfRange(rawData, offset, offset + length);
            this.autoHeader = new AutoHeader(this.rawData, obj);
        }

        @Override public AutoHeader getHeader() { return autoHeader; }
        @Override public Packet getPayload() { return null; }
        @Override public AutoBuilder getBuilder() { return new AutoBuilder(); }
        @Override public int length() { return rawData.length; }
        @Override public String toString() { return "[AutoPacket " + clazz.getSimpleName() + "]"; }
        @Override public byte[] getRawData() { return rawData.clone(); }
    }

    private final class AutoHeader extends AbstractPacket.AbstractHeader {
        private static final long serialVersionUID = 1L;
        private final byte[] rawData;
        private final T obj;

        AutoHeader(byte[] rawData, T obj) {
            this.rawData = rawData;
            this.obj = obj;
        }

        @Override public int length() { return rawData.length; }
        @Override public byte[] getRawData() { return rawData.clone(); }
        @Override public List<byte[]> getRawFields() {
            // AutoHeader 不细分子字段,整体作为单一原始字段返回。
            return Collections.singletonList(rawData.clone());
        }
        @Override public String toString() { return obj != null ? obj.toString() : Arrays.toString(rawData); }
    }

    public final class AutoBuilder extends AbstractPacket.AbstractBuilder {
        private T obj;

        AutoBuilder() {
            try {
                this.obj = clazz.getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public AutoBuilder withObject(T obj) {
            this.obj = obj;
            return this;
        }

        @Override public AutoPacket build() {
            byte[] data = serialize(obj);
            return new AutoPacket(data, 0, data.length, obj);
        }
    }
}
