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
            // LIST 校验
            if (fi.elementClass != void.class) {
                // count 驱动校验:sentinel 驱动的 LIST 不需要 countField(二者互斥)
                if (fi.sentinel < 0) {
                    if (fi.countField.isEmpty()) {
                        throw new IllegalArgumentException(
                                "LIST field '" + fi.name + "' missing countField");
                    }
                    Integer refOrder = nameToOrder.get(fi.countField);
                    if (refOrder == null) {
                        throw new IllegalArgumentException(
                                "LIST field '" + fi.name + "' countField references unknown field '" + fi.countField + "'");
                    }
                    if (refOrder >= fi.order) {
                        throw new IllegalArgumentException(
                                "LIST field '" + fi.name + "' countField references '" + fi.countField
                                        + "' which is not earlier in order (forward ref forbidden)");
                    }
                }
                // elementClass + 边界校验:count 与 sentinel 驱动都适用
                if (!fi.elementClass.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolPacket.class)) {
                    throw new IllegalArgumentException(
                            "LIST field '" + fi.name + "' elementClass " + fi.elementClass.getName()
                                    + " is not a @ProtocolPacket entity");
                }
                validateElementBoundary(fi.elementClass);
            }
            // sentinel 校验(Phase 2b)
            if (fi.sentinel >= 0) {
                if (fi.sentinel > 0xFF) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "' sentinel=" + fi.sentinel + " out of range (0x00-0xFF)");
                }
                if (!fi.countField.isEmpty()) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': sentinel and countField are mutually exclusive");
                }
                if (!fi.lengthField.isEmpty()) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': sentinel and lengthField are mutually exclusive");
                }
            }
        }
    }

    /**
     * 校验 LIST 元素能否自定边界:最后一个 @ProtocolField 字段必须能定长度
     * (有 size>0、或有 lengthField、或本身是 LIST/靠 countField)。
     * 否则元素会「吃剩余字节」,在 count 驱动场景下无法正确分割。
     */
    private static void validateElementBoundary(Class<?> elementClass) {
        java.lang.reflect.Field[] fields = elementClass.getDeclaredFields();
        java.lang.reflect.Field lastProtocolField = null;
        for (java.lang.reflect.Field f : fields) {
            if (f.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolField.class)) {
                lastProtocolField = f;
            }
        }
        if (lastProtocolField == null) {
            return;
        }
        com.example.demo.protocol.annotation.ProtocolField ann =
                lastProtocolField.getAnnotation(com.example.demo.protocol.annotation.ProtocolField.class);
        boolean selfBounded = ann.size() > 0
                || !ann.lengthField().isEmpty()
                || ann.elementClass() != void.class;
        if (!selfBounded) {
            throw new IllegalArgumentException(
                    "LIST element " + elementClass.getName() + " last field '"
                            + lastProtocolField.getName() + "' has no self-boundary "
                            + "(no size/lengthField and not LIST): count-driven LIST cannot split it");
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
                // 反序列化路径:尚未读取嵌套对象值,无法序列化取尺寸。
                // 对变长 NESTED 字段(最后一个字段)用「吃掉剩余字节」,
                // 故把剩余位数传给 resolveSize(其余路径忽略此值)。
                int remainingBits = length * 8 - cursor.bitOffset();
                long size = resolveSize(fi, obj, ctx, true, remainingBits);
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
                long size = resolveSize(fi, obj, ctx, false, 0);
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
                long size = resolveSize(fi, obj, ctx, false, 0);
                writeValue(fi, obj, cursor, (int) size, ctx);
            }
            if (payloadField != null && payloadData != null) {
                cursor.writeBytes(payloadData);
            }
            return cursor.bytes();
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize " + clazz.getName() + ": " + e.getMessage(), e);
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

    // ---- 动态尺寸解析(Task 6/7 扩充 lengthField/presentIf;Task 10 扩充动态 NESTED) ----
    private long resolveSize(FieldInfo fi, Object obj, FieldContext ctx, boolean deserialize, int remainingBits) throws Exception {
        // -1. sentinel:数据位数 + 8(标记字节)
        if (fi.sentinel >= 0) {
            return sentinelTotalBits(fi, obj);
        }
        // 0. LIST:总位数 = 各元素 serialize 后累加
        if (effectiveType(fi) == FieldType.LIST) {
            return listTotalBits(fi, obj);
        }
        // 1. 钩子优先
        if (obj instanceof DynamicSize ds) {
            long s = ds.computeSize(fi.name, ctx);
            if (s >= 0) {
                return s;
            }
        }
        // 2. 声明式 lengthField(Phase 2b 加 lengthAdjust 偏移)
        if (!fi.lengthField.isEmpty() && ctx.hasRead(fi.lengthField)) {
            int ref = ctx.getInt(fi.lengthField);
            if (fi.lengthUnit == LengthUnit.BYTES) {
                return (ref + fi.lengthAdjust) * 8L;
            }
            return ref;  // BITS 单位不应用字节偏移
        }
        // 3. NESTED:嵌套实体的位长度(取整到整字节——readBytes/writeBytes 要求整字节 & 字节对齐)
        if (effectiveType(fi) == FieldType.NESTED) {
            // 3a. 嵌套实体本身全为固定 size 字段 → 直接按其字段 size 求和取整。
            //     覆盖 Outer/BitFields 等全固定嵌套用例。
            try {
                long raw = fixedBitSize(fi.field.getType());
                return ((raw + 7) / 8) * 8;
            } catch (IllegalStateException dynamicNested) {
                // 3b. 嵌套实体含变长字段(如 Ipv4Header.options,无 lengthField、size<=0)。
                //     - 序列化路径:对象值在手,直接序列化取实际字节数(*8 取整到字节,本身已是整字节)。
                //     - 反序列化路径:尚未读取对象值,无法序列化;此时「吃掉剩余字节」(变长 NESTED
                //       只能作为帧中最后一个字段,Phase 1 限制)。remainingBits 为负(无剩余字节)说明该
                //       字段并非最后一个 → 抛出,避免静默截断/破坏后续字段。
                if (!deserialize) {
                    fi.field.setAccessible(true);
                    Object nestedValue = fi.field.get(obj);
                    if (nestedValue == null) {
                        throw new IllegalStateException(
                                "cannot resolve size of dynamic NESTED field " + fi.name
                                        + ": nested value is null during serialize");
                    }
                    byte[] nestedBytes = serializeNested(codecFor(fi.field.getType()), nestedValue);
                    return nestedBytes.length * 8L;
                }
                if (remainingBits < 0) {
                    throw new IllegalStateException(
                            "cannot resolve size of dynamic NESTED field " + fi.name
                                    + " in " + clazz.getName()
                                    + ": mid-frame dynamic NESTED unsupported in Phase 1 "
                                    + "(only the last field may consume remaining bytes)", dynamicNested);
                }
                return remainingBits;
            }
        }
        // 4. 固定 size
        if (fi.size > 0) {
            return fi.size;
        }
        throw new IllegalStateException("cannot resolve size of field " + fi.name);
    }

    /** 计算 LIST 字段总位数(供 resolveSize 用;主要服务序列化端两遍循环)。 */
    private long listTotalBits(FieldInfo fi, Object obj) throws Exception {
        fi.field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.List<Object> list = (java.util.List<Object>) fi.field.get(obj);
        if (list == null) {
            return 0;
        }
        ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
        long total = 0;
        for (Object elem : list) {
            total += serializeNested(elementCodec, elem).length * 8L;
        }
        return total;
    }

    /**
     * 计算 sentinel 字段总位数(供 resolveSize 序列化用):数据位数 + 8(标记字节)。
     * - BYTES:数据 = 字段当前字节数
     * - LIST:数据 = 各元素 serialize 累加
     */
    private long sentinelTotalBits(FieldInfo fi, Object obj) throws Exception {
        fi.field.setAccessible(true);
        Object value = fi.field.get(obj);
        long dataBits;
        if (value instanceof byte[] bytes) {
            dataBits = bytes.length * 8L;
        } else if (value instanceof java.util.List<?> list) {
            ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
            long total = 0;
            for (Object elem : list) {
                total += serializeNested(elementCodec, elem).length * 8L;
            }
            dataBits = total;
        } else {
            throw new IllegalStateException("sentinel field " + fi.name + " must be byte[] or List");
        }
        return dataBits + 8;  // + 标记字节
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
        // sentinel 反序列化(跨 BYTES/LIST,优先)
        if (fi.sentinel >= 0) {
            return readSentinelValue(fi, cursor);
        }
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
            // LIST 占位:count 驱动数组的读取由 Phase 2a Task 4 实现。
            case LIST -> {
                int count = ctx.getInt(fi.countField);
                ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
                java.util.List<Object> list = new java.util.ArrayList<>(count);
                for (int i = 0; i < count; i++) {
                    byte[] rest = cursor.remainingFromCursor();
                    Object elem = elementCodec.deserialize(rest, 0, rest.length);
                    list.add(elem);
                    int consumedBits = (int) (serializeNested(elementCodec, elem).length * 8L);
                    cursor.skipBits(consumedBits);
                }
                yield list;
            }
        };
    }

    /**
     * sentinel 反序列化:读到标记字节停。
     * - BYTES:逐字节读到 == sentinel,消费标记,返回之前的字节
     * - LIST:peek → 命中 sentinel 则消费标记+停;否则读一个元素,循环
     */
    private Object readSentinelValue(FieldInfo fi, BitCursor cursor) throws Exception {
        if (effectiveType(fi) == FieldType.LIST) {
            ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
            java.util.List<Object> list = new java.util.ArrayList<>();
            while (true) {
                int peek = cursor.peekByte();
                if (peek == fi.sentinel) {
                    cursor.skipBits(8);  // 消费标记字节
                    break;
                }
                if (peek < 0) {
                    throw new IllegalStateException(
                            "sentinel field " + fi.name + ": reached end of data without marker " + fi.sentinel);
                }
                byte[] rest = cursor.remainingFromCursor();
                Object elem = elementCodec.deserialize(rest, 0, rest.length);
                list.add(elem);
                cursor.skipBits((int) (serializeNested(elementCodec, elem).length * 8L));
            }
            return list;
        } else {
            // BYTES:逐字节读
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            while (true) {
                int peek = cursor.peekByte();
                if (peek == fi.sentinel) {
                    cursor.skipBits(8);  // 消费标记
                    break;
                }
                if (peek < 0) {
                    throw new IllegalStateException(
                            "sentinel field " + fi.name + ": reached end of data without marker " + fi.sentinel);
                }
                bos.write((int) cursor.readBits(8));  // 读一字节(取低8位)
            }
            return bos.toByteArray();
        }
    }

    private void writeValue(FieldInfo fi, Object obj, BitCursor cursor, int size, FieldContext ctx) throws Exception {
        // sentinel 序列化:写数据 + 追加标记字节
        if (fi.sentinel >= 0) {
            writeSentinelValue(fi, obj, cursor);
            return;
        }
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
            case LIST -> {
                @SuppressWarnings("unchecked")
                java.util.List<Object> list = (java.util.List<Object>) value;
                int declared = ctx.getInt(fi.countField);
                if (declared != list.size()) {
                    throw new IllegalStateException(
                            "LIST field '" + fi.name + "': countField '" + fi.countField
                                    + "'=" + declared + " but list.size()=" + list.size());
                }
                ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
                for (Object elem : list) {
                    cursor.writeBytes(serializeNested(elementCodec, elem));
                }
            }
        }
    }

    /** sentinel 序列化:写数据 + 追加标记字节。 */
    private void writeSentinelValue(FieldInfo fi, Object obj, BitCursor cursor) throws Exception {
        fi.field.setAccessible(true);
        Object value = fi.field.get(obj);
        if (value instanceof byte[] bytes) {
            cursor.writeBytes(bytes);
        } else if (value instanceof java.util.List<?> list) {
            ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
            for (Object elem : list) {
                cursor.writeBytes(serializeNested(elementCodec, elem));
            }
        } else {
            throw new IllegalStateException("sentinel field " + fi.name + " must be byte[] or List");
        }
        cursor.writeBits(fi.sentinel, 8);  // 追加标记字节
    }

    private FieldType effectiveType(FieldInfo fi) {
        if (fi.type != FieldType.INT) {
            return fi.type; // 显式指定
        }
        // INT 默认:按 Java 类型推断(BYTES/STRING/NESTED/LIST)
        Class<?> t = fi.field.getType();
        if (java.util.List.class.isAssignableFrom(t)) {
            return FieldType.LIST;
        }
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
        // enum 字段:type 是 ProtocolEnum 的 enum
        if (ProtocolEnum.class.isAssignableFrom(type) && Enum.class.isAssignableFrom(type)) {
            return enumFromValue(type, (int) val);
        }
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

    /** 把整数转成 enum 常量;找不到匹配值返回 UnknownEnumValue(携带原始 int)。 */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static Object enumFromValue(Class<?> enumType, int value) {
        Object[] constants = enumType.getEnumConstants();
        if (constants != null) {
            for (Object c : constants) {
                if (((ProtocolEnum) c).value() == value) {
                    return c;
                }
            }
        }
        return new UnknownEnumValue(value, (Class<? extends Enum<?>>) enumType);
    }

    private static long convertFromFieldType(Object value) {
        if (value instanceof ProtocolEnum e) {
            return e.value();
        }
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
        final String countField;
        final Class<?> elementClass;
        final int lengthAdjust;
        final int sentinel;

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
            this.countField = ann.countField();
            this.elementClass = ann.elementClass();
            this.lengthAdjust = ann.lengthAdjust();
            this.sentinel = ann.sentinel();
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
            this.countField = "";
            this.elementClass = void.class;
            this.lengthAdjust = 0;
            this.sentinel = -1;
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
