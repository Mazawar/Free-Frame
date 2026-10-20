package com.netproto.core;

import com.netproto.annotation.Payload;

import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.util.*;

public final class ProtocolCodec<T> implements PacketCodec<T> {

    private final Class<T> clazz;
    private final List<FieldInfo> fixedFields; // 按 order 排序
    private final FieldInfo payloadField;      // @Payload 字段(向后兼容)

    /** 最近一次 deserialize 的头部(固定字段)位宽;headerBytes() 用。分派线程内单线程使用。 */
    private int lastHeaderBits;
    /** 最近一次 deserialize 各顶层字段的位区间(相对本层起点);lastFieldRanges() 用。 */
    private final java.util.Map<String, int[]> lastFieldRanges = new HashMap<>();
    /** 当前 deserialize 的层边界(相对游标 baseByte 的位偏移),untilEnd 循环用。 */
    private int layerEndBits;

    public ProtocolCodec(Class<T> clazz) {
        this.clazz = clazz;
        List<FieldInfo> fixed = new ArrayList<>();
        FieldInfo payload = null;

        for (Field f : clazz.getDeclaredFields()) {
            if (f.isAnnotationPresent(Payload.class)) {
                payload = FieldInfo.forPayload(f);
            } else if (f.isAnnotationPresent(com.netproto.annotation.ProtocolField.class)) {
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
            // presentIf 校验(只查字段存在;位索引语法 name[n] 查基名)
            if (!fi.presentIf.isBlank()) {
                int eq = fi.presentIf.indexOf("==");
                String left = eq >= 0 ? fi.presentIf.substring(0, eq).trim() : fi.presentIf.trim();
                String base = left.contains("[") ? left.substring(0, left.indexOf('[')) : left;
                if (!nameToOrder.containsKey(base)) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "' presentIf references unknown field '" + base + "'");
                }
            }
            // LIST 校验
            if (fi.elementClass != void.class) {
                // count 驱动校验:sentinel/sentinelOn/untilEnd 驱动的 LIST 不需要 countField(互斥)
                if (fi.sentinel < 0 && fi.sentinelBytes.length == 0
                        && fi.sentinelOn.isEmpty() && !fi.untilEnd) {
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
            if (!fi.elementClass.isAnnotationPresent(com.netproto.annotation.Protocol.class)) {
                throw new IllegalArgumentException(
                        "LIST field '" + fi.name + "' elementClass " + fi.elementClass.getName()
                                + " is not a @Protocol entity");
            }
                validateElementBoundary(fi.elementClass);
                // countUnit=BYTES:元素须全定长(个数 = 字节数/元素字节)
                if (fi.countUnit == com.netproto.annotation.CountUnit.BYTES) {
                    try {
                        fixedBitSize(fi.elementClass);
                    } catch (IllegalStateException e) {
                        throw new IllegalArgumentException(
                                "field '" + fi.name + "': countUnit=BYTES requires fixed-size elements", e);
                    }
                }
            }
            // sentinel 校验(Phase 2b;单/多字节终结符同规则)
            if (fi.hasSentinel()) {
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
            // sentinelOn 校验(Phase 2c2:元素内 sentinel)
            if (!fi.sentinelOn.isEmpty()) {
                if (!fi.countField.isEmpty()) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': sentinelOn and countField are mutually exclusive");
                }
                if (fi.hasSentinel()) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': sentinelOn and sentinel are mutually exclusive");
                }
            }
            // custom(L2 逃生舱)校验:接管字段的一切尺寸来源,禁止与声明式尺寸混用
            if (fi.custom != null) {
                if (fi.size > 0) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': custom and size are mutually exclusive");
                }
                if (!fi.lengthField.isEmpty() || !fi.countField.isEmpty()
                        || fi.hasSentinel() || !fi.sentinelOn.isEmpty() || fi.untilEnd) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': custom is mutually exclusive with"
                                    + " lengthField/countField/sentinel/sentinelOn/untilEnd");
                }
            }
            // untilEnd(循环·耗尽驱动)校验
            if (fi.untilEnd) {
                if (!fi.countField.isEmpty() || fi.hasSentinel() || !fi.sentinelOn.isEmpty()
                        || !fi.lengthField.isEmpty()) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': untilEnd is mutually exclusive with"
                                    + " countField/sentinel/sentinelOn/lengthField");
                }
                if (fi.elementClass == void.class) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': untilEnd requires elementClass");
                }
                for (java.lang.reflect.Field ef : fi.elementClass.getDeclaredFields()) {
                    if (ef.isAnnotationPresent(Payload.class)) {
                        throw new IllegalArgumentException(
                                "field '" + fi.name + "': untilEnd element "
                                        + fi.elementClass.getName() + " must not have a @Payload field"
                                        + " (element must be self-bounded)");
                    }
                }
            }
            // FLOAT/BCD 类型校验(validateReferences 为 static,此处内联类型判定)
            Class<?> ft = fi.field.getType();
            boolean isFloat = fi.type == FieldType.FLOAT
                    || ft == float.class || ft == Float.class
                    || ft == double.class || ft == Double.class;
            if (isFloat && fi.size != 32 && fi.size != 64) {
                throw new IllegalArgumentException(
                        "field '" + fi.name + "': FLOAT requires size 32 or 64, got " + fi.size);
            }
            if (fi.type == FieldType.BCD && (fi.size <= 0 || fi.size % 4 != 0)) {
                throw new IllegalArgumentException(
                        "field '" + fi.name + "': BCD requires size in nibbles (multiples of 4 bits)");
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
            if (f.isAnnotationPresent(com.netproto.annotation.ProtocolField.class)) {
                lastProtocolField = f;
            }
        }
        if (lastProtocolField == null) {
            return;
        }
        com.netproto.annotation.ProtocolField ann =
                lastProtocolField.getAnnotation(com.netproto.annotation.ProtocolField.class);
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
            java.lang.reflect.Constructor<T> ctor = clazz.getDeclaredConstructor();
            ctor.setAccessible(true);   // 支持包私有协议类
            T obj = ctor.newInstance();
            FieldContext.Impl ctx = (FieldContext.Impl) FieldContext.create(obj);
            BitCursor cursor = new BitCursor(rawData, offset);
            this.layerEndBits = length * 8;
            this.lastFieldRanges.clear();

            for (FieldInfo fi : fixedFields) {
                if (!evalPresentIf(fi, ctx)) {
                    continue; // 条件不满足:不读字节、不入 ctx
                }
                int startBit = cursor.bitOffset();
                Object value;
                if (fi.custom != null) {
                    // L2 逃生舱:自定义编解码器全权接管该字段(自行推进游标)
                    int remainingBytes = Math.max(0, (length * 8 - cursor.bitOffset()) / 8);
                    value = fi.custom.read(cursor, ctx, remainingBytes);
                } else {
                    // 反序列化路径:尚未读取嵌套对象值,无法序列化取尺寸。
                    // 对变长 NESTED 字段(最后一个字段)用「吃掉剩余字节」,
                    // 故把剩余位数传给 resolveSize(其余路径忽略此值)。
                    int remainingBits = length * 8 - cursor.bitOffset();
                    long size = resolveSize(fi, obj, ctx, true, remainingBits);
                    value = readValue(fi, cursor, (int) size, ctx);
                }
                int endBit = cursor.bitOffset();
                if (endBit > startBit) {
                    this.lastFieldRanges.put(fi.name, new int[]{startBit, endBit});
                }
                fi.field.setAccessible(true);
                fi.field.set(obj, value);
                ctx.put(fi.name, value);
            }
            this.lastHeaderBits = cursor.bitOffset();

            // 向后兼容:@Payload 取剩余字节
            if (payloadField != null) {
                int consumedBits = cursor.bitOffset();
                int consumedBytes = (consumedBits + 7) / 8;
                if (length > consumedBytes) {
                    payloadField.field.setAccessible(true);
                    payloadField.field.set(obj, Arrays.copyOfRange(rawData, offset + consumedBytes, offset + length));
                    this.lastFieldRanges.put(payloadField.name, new int[]{consumedBits, length * 8});
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
                if (!evalPresentIf(fi, ctx)) {
                    continue;
                }
                if (fi.custom != null) {
                    fi.field.setAccessible(true);
                    totalBits += fi.custom.sizeOf(fi.field.get(obj));
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
            // 记录校验和字段的偏移(field → 起始字节偏移),供第三步回写
            java.util.Map<String, Integer> checksumOffsets = new java.util.HashMap<>();
            for (FieldInfo fi : fixedFields) {
                if (!evalPresentIf(fi, ctx)) {
                    continue;
                }
                if (fi.custom != null) {
                    fi.field.setAccessible(true);
                    fi.custom.write(cursor, ctx, fi.field.get(obj));
                    continue;
                }
                long size = resolveSize(fi, obj, ctx, false, 0);
                if (fi.checksumField) {
                    // 校验和字段:记录起始字节偏移,强制写 0
                    int startByte = cursor.bitOffset() / 8;
                    checksumOffsets.put(fi.name, startByte);
                    cursor.writeBits(0L, (int) size);
                } else {
                    writeValue(fi, obj, cursor, (int) size, ctx);
                }
            }
            if (payloadField != null && payloadData != null) {
                cursor.writeBytes(payloadData);
            }
            // 第三步:若实体实现 Checksum,对每个校验和字段 compute → 回写
            if (obj instanceof Checksum cs) {
                byte[] bytes = cursor.bytes();
                for (FieldInfo fi : fixedFields) {
                    if (!fi.checksumField) continue;
                    long computed = cs.compute(fi.name, bytes);
                    if (computed < 0) continue;  // 钩子不接管
                    int size = (int) resolveSize(fi, obj, ctx, false, 0);
                    int truncated = (int) (computed & (size >= 64 ? -1L : ((1L << size) - 1)));
                    int startByte = checksumOffsets.get(fi.name);
                    writeBitsAtOffset(bytes, startByte, size, truncated);
                }
                return bytes;
            }
            return cursor.bytes();
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize " + clazz.getName() + ": " + e.getMessage(), e);
        }
    }

    /** 把 value 的低 size 位写进 bytes 从 startByte 字节起的 MSB 优先位置(供校验和回写)。 */
    private static void writeBitsAtOffset(byte[] bytes, int startByte, int size, long value) {
        for (int i = 0; i < size; i++) {
            int absBit = startByte * 8 + i;
            int byteIdx = absBit / 8;
            int bitInByte = 7 - (absBit % 8);
            long bit = (value >> (size - 1 - i)) & 1L;
            if (bit == 1) {
                bytes[byteIdx] |= (byte) (1 << bitInByte);
            } else {
                bytes[byteIdx] &= (byte) ~(1 << bitInByte);
            }
        }
    }

    /** 求值 presentIf(预编译 AST,严格模式:未知/未读字段抛 IllegalArgumentException)。 */
    private static boolean evalPresentIf(FieldInfo fi, FieldContext ctx) {
        if (fi.presentIfNode == null) {
            return true;
        }
        try {
            return fi.presentIfNode.eval(name -> resolveCtxLong(ctx, name)) != 0;
        } catch (Expr.UnknownIdentifier e) {
            throw new IllegalArgumentException(
                    "presentIf of '" + fi.name + "': " + e.getMessage(), e);
        }
    }

    private static long resolveCtxLong(FieldContext ctx, String name) {
        // 位索引标识符 name[n]:位图驱动条件的一等语法(与 when 侧一致)
        Long bit = Expr.resolveBitIndex(n -> ctx.hasRead(n) ? ctx.get(n) : null, name);
        if (bit != null) {
            return bit;
        }
        if (!ctx.hasRead(name)) {
            throw new Expr.UnknownIdentifier(name);
        }
        Object v = ctx.get(name);
        if (v instanceof Number n) {
            return n.longValue();
        }
        throw new IllegalArgumentException("presentIf field not numeric: " + name);
    }

    // ---- 动态尺寸解析(Task 6/7 扩充 lengthField/presentIf;Task 10 扩充动态 NESTED) ----
    private long resolveSize(FieldInfo fi, Object obj, FieldContext ctx, boolean deserialize, int remainingBits) throws Exception {
        // -2. LIST_TLV:总位数 = 各元素(type 1B + length 1B + value)累加 + (endMarker 则 +8)
        if (effectiveType(fi) == FieldType.LIST_TLV) {
            return tlvTotalBits(fi, obj);
        }
        // -1. sentinel:序列化路径按当前值算位数;反序列化路径尺寸无意义
        //     (readSentinelValue 自行扫描标记),直接吃剩余字节。
        if (fi.hasSentinel()) {
            return deserialize ? remainingBits : sentinelTotalBits(fi, obj);
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
        // 2. 声明式 lengthField(Phase 2b 加 lengthAdjust 偏移;lengthAscii 支持 LLVAR 文本数字长度)
        if (!fi.lengthField.isEmpty() && ctx.hasRead(fi.lengthField)) {
            Object refVal = ctx.get(fi.lengthField);
            long ref;
            if (refVal instanceof Number n) {
                ref = n.longValue();
            } else if (fi.lengthAscii && refVal instanceof String str) {
                try {
                    ref = Long.parseLong(str.trim());
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException(
                            "lengthField '" + fi.lengthField + "' of '" + fi.name
                                    + "': not ASCII decimal digits: \"" + str + "\"");
                }
            } else {
                throw new IllegalArgumentException(
                        "lengthField '" + fi.lengthField + "' of '" + fi.name + "' is not numeric"
                                + (fi.lengthAscii ? "" : " (ASCII digits need lengthAscii=true)"));
            }
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
        // count 驱动且计数字段未设置(0):按列表长度自动回填(ELEMENTS=个数/BYTES=字节)。
        // 在第一遍(算总位数)完成,早于任何字段写入。BYTES 需要元素定长,ELEMENTS 不需要。
        if (!fi.countField.isEmpty() && !fi.untilEnd) {
            java.lang.reflect.Field cf = findFieldByName(obj.getClass(), fi.countField);
            if (cf != null && numberFieldValue(cf, obj) == 0) {
                long v;
                if (fi.countUnit == com.netproto.annotation.CountUnit.BYTES) {
                    v = list.size() * (fixedBitSize(fi.elementClass) / 8);
                } else {
                    v = list.size();
                }
                cf.setAccessible(true);
                if (cf.getType() == int.class || cf.getType() == Integer.class) {
                    cf.set(obj, (int) v);
                } else if (cf.getType() == long.class || cf.getType() == Long.class) {
                    cf.set(obj, v);
                } else if (cf.getType() == short.class || cf.getType() == Short.class) {
                    cf.set(obj, (short) v);
                } else if (cf.getType() == byte.class || cf.getType() == Byte.class) {
                    cf.set(obj, (byte) v);
                }
            }
        }
        ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
        long total = 0;
        for (Object elem : list) {
            total += serializeNested(elementCodec, elem).length * 8L;
        }
        if (!fi.sentinelOn.isEmpty()) {
            total += fi.sentinelOnSize;  // 末尾追加 sentinel 标记位
        }
        return total;
    }

    /** 计算 LIST_TLV 字段总位数(供 resolveSize 序列化用)。 */
    private long tlvTotalBits(FieldInfo fi, Object obj) throws Exception {
        fi.field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.List<Object> list = (java.util.List<Object>) fi.field.get(obj);
        long total = 0;
        for (Object elem : list) {
            byte[] valueBytes = serializeNested(codecFor(elem.getClass()), elem);
            total += 8 + 8 + valueBytes.length * 8L;
        }
        if (fi.tlvEndMarker >= 0) {
            total += 8;  // sentinel 字节
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
        if (value == null) {
            dataBits = 0;  // 未赋值视为空数据(仍追加标记字节)
        } else if (value instanceof String s) {
            dataBits = s.getBytes(Charset.forName(fi.charset)).length * 8L;
        } else if (value instanceof byte[] bytes) {
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
        return dataBits + 8L * fi.sentinelByteLen();  // + 标记字节(单/多字节)
    }

    /**
     * 计算某实体类型「全固定字段」的位总和(供 NESTED 定长解析)。
     * 任一 {@code @ProtocolField} 字段无确定 size(≤0)即抛异常——这意味着
     * NESTED-in-middle 且变长的情形在 Phase 1 不支持(可接受)。
     */
    private static long fixedBitSize(Class<?> type) {
        long sum = 0;
        for (Field f : type.getDeclaredFields()) {
            if (f.isAnnotationPresent(com.netproto.annotation.ProtocolField.class)) {
                com.netproto.annotation.ProtocolField ann =
                        f.getAnnotation(com.netproto.annotation.ProtocolField.class);
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

    /** 查 elementClass 里 sentinelOn 字段的 size;字段不存在或 size<=0 抛异常。 */
    private static int lookupSentinelOnSize(Class<?> elementClass, String sentinelOn) {
        for (Field f : elementClass.getDeclaredFields()) {
            if (f.isAnnotationPresent(com.netproto.annotation.ProtocolField.class)
                    && f.getName().equals(sentinelOn)) {
                int sz = f.getAnnotation(com.netproto.annotation.ProtocolField.class).size();
                if (sz <= 0) {
                    throw new IllegalArgumentException(
                            "sentinelOn field '" + sentinelOn + "' in " + elementClass.getName()
                                    + " has no fixed size");
                }
                return sz;
            }
        }
        throw new IllegalArgumentException(
                "sentinelOn field '" + sentinelOn + "' not found in " + elementClass.getName());
    }

    /** 按名查找字段(含本类声明)。 */
    private static java.lang.reflect.Field findFieldByName(Class<?> type, String name) {
        for (java.lang.reflect.Field f : type.getDeclaredFields()) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
    }

    /** 读数值字段为 long(非数值/不可读返回 0)。 */
    private static long numberFieldValue(java.lang.reflect.Field f, Object obj) {
        if (f == null) {
            return 0;
        }
        try {
            f.setAccessible(true);
            Object v = f.get(obj);
            return v instanceof Number n ? n.longValue() : 0;
        } catch (IllegalAccessException e) {
            return 0;
        }
    }

    /** LIST/TLV 元素级字节区间(字段↔字节联动的细粒度数据源,key 形如 "items[2]")。 */
    private void putElemRange(String field, int index, int fromBit, int toBit) {
        if (toBit > fromBit) {
            this.lastFieldRanges.put(field + "[" + index + "]", new int[]{fromBit, toBit});
        }
    }

    /** 按 n 字节反转(LITTLE endian 整数与线上位序互转,size ≤ 64 位)。 */
    private static long reverseBytes(long v, int n) {
        long out = 0;
        for (int i = 0; i < n; i++) {
            out = (out << 8) | ((v >>> (8 * i)) & 0xFF);
        }
        return out;
    }

    private Object readValue(FieldInfo fi, BitCursor cursor, int size, FieldContext ctx) throws Exception {
        // sentinel 反序列化(跨 BYTES/LIST,优先;单/多字节终结符同路径)
        if (fi.hasSentinel()) {
            return readSentinelValue(fi, cursor);
        }
        FieldType type = effectiveType(fi);
        return switch (type) {
            case INT, UNSIGNED -> {
                long v = cursor.readBits(size);
                if (fi.endian == com.netproto.annotation.Endian.LITTLE) {
                    v = reverseBytes(v, size / 8);
                }
                yield convertToFieldType(fi.field.getType(), v, type == FieldType.UNSIGNED, fi.enumClass, fi.flagClass);
            }
            case FLOAT -> {
                if (size == 32) {
                    yield Float.intBitsToFloat((int) cursor.readBits(32));
                }
                yield Double.longBitsToDouble(cursor.readBits(64));
            }
            case BCD -> {
                long raw = cursor.readBits(size);
                long v = 0;
                for (int shift = size - 4; shift >= 0; shift -= 4) {
                    int d = (int) ((raw >> shift) & 0xF);
                    if (d > 9) {
                        throw new IllegalStateException(
                                "BCD field '" + fi.name + "': invalid digit 0x" + Integer.toHexString(d));
                    }
                    v = v * 10 + d;
                }
                yield convertToFieldType(fi.field.getType(), v, false, fi.enumClass, fi.flagClass);
            }
            case BYTES -> cursor.readBytes(size);
            case STRING -> new String(cursor.readBytes(size), Charset.forName(fi.charset));
            case NESTED -> {
                ProtocolCodec<?> nested = codecFor(fi.field.getType());
                byte[] seg = cursor.readBytes(size);
                yield nested.deserialize(seg, 0, seg.length);
            }
            // LIST 占位:count 驱动数组的读取由 Phase 2a Task 4 实现。
            case LIST -> {
                ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
                java.util.List<Object> list = new java.util.ArrayList<>();
                if (!fi.sentinelOn.isEmpty()) {
                    // 元素内 sentinel:peek sentinelOn 字段值,==sentinelValue 则停
                    while (true) {
                        long peek = cursor.peekBits(fi.sentinelOnSize);
                        if (peek < 0) break;  // 到末尾
                        if (peek == fi.sentinelValue) {
                            cursor.skipBits(fi.sentinelOnSize);  // 消费结束标记
                            break;
                        }
                        int before = cursor.bitOffset();
                        byte[] rest = cursor.remainingFromCursor();
                        Object elem = elementCodec.deserialize(rest, 0, rest.length);
                        list.add(elem);
                        cursor.skipBits((int) (serializeNested(elementCodec, elem).length * 8L));
                        putElemRange(fi.name, list.size() - 1, before, cursor.bitOffset());
                    }
                } else if (fi.untilEnd) {
                    // 耗尽驱动:读到本层缓冲区末尾为止(元素须自定边界,注册期已校验)
                    while (cursor.bitOffset() < layerEndBits) {
                        int before = cursor.bitOffset();
                        byte[] rest = cursor.remainingFromCursor();
                        Object elem = elementCodec.deserialize(rest, 0, rest.length);
                        list.add(elem);
                        int elemBits = (int) (serializeNested(elementCodec, elem).length * 8L);
                        if (elemBits == 0) {
                            break;  // 防 0 字节元素死循环
                        }
                        cursor.skipBits(elemBits);
                        putElemRange(fi.name, list.size() - 1, before, cursor.bitOffset());
                        if (before + elemBits > layerEndBits) {
                            // 元素越过层边界(数据畸形):保留已读元素,停止循环
                            break;
                        }
                    }
                } else {
                    // count 驱动(Phase 2a 原逻辑;countUnit=BYTES 时按元素定长换算个数)
                    int count = ctx.getInt(fi.countField);
                    if (fi.countUnit == com.netproto.annotation.CountUnit.BYTES) {
                        long elemBits = fixedBitSize(fi.elementClass);
                        count = (int) ((count * 8L + elemBits - 1) / elemBits);
                    }
                    for (int i = 0; i < count; i++) {
                        int before = cursor.bitOffset();
                        byte[] rest = cursor.remainingFromCursor();
                        Object elem = elementCodec.deserialize(rest, 0, rest.length);
                        list.add(elem);
                        cursor.skipBits((int) (serializeNested(elementCodec, elem).length * 8L));
                        putElemRange(fi.name, i, before, cursor.bitOffset());
                    }
                }
                yield list;
            }
            case LIST_TLV -> {
                yield readTlvValue(fi, cursor);
            }
        };
    }

    /** LIST_TLV 反序列化:循环读 type+length+value,sentinel 终止,未知 type 跳过。 */
    private Object readTlvValue(FieldInfo fi, BitCursor cursor) throws Exception {
        Class<?> contextClass = fi.field.getDeclaringClass();
        java.util.List<Object> list = new java.util.ArrayList<>();
        while (true) {
            int peek = cursor.peekByte();
            if (peek < 0) break;  // 到末尾
            if (fi.tlvEndMarker >= 0 && peek == fi.tlvEndMarker) {
                cursor.skipBits(8);  // 消费 sentinel
                break;
            }
            int type = (int) cursor.readBits(8);
            int length = (int) cursor.readBits(8);
            String className = fi.dispatchMap.get(type);
            if (className == null) {
                cursor.skipBits(length * 8);  // 未知 type 跳过
                continue;
            }
            int elemStart = cursor.bitOffset() - 16;   // 区间含 type+len 头
            Class<?> elemClass = resolveDispatchClass(className, contextClass);
            byte[] valueBytes = cursor.readBytes(length * 8);
            Object elem = codecFor(elemClass).deserialize(valueBytes, 0, valueBytes.length);
            list.add(elem);
            putElemRange(fi.name, list.size() - 1, elemStart, cursor.bitOffset());
        }
        return list;
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
                if (atSentinelMarker(fi, cursor)) {
                    cursor.skipBits(8 * fi.sentinelByteLen());  // 消费标记
                    break;
                }
                if (cursor.peekByte() < 0) {
                    throw new IllegalStateException(
                            "sentinel field " + fi.name + ": reached end of data without marker");
                }
                int before = cursor.bitOffset();
                byte[] rest = cursor.remainingFromCursor();
                Object elem = elementCodec.deserialize(rest, 0, rest.length);
                list.add(elem);
                cursor.skipBits((int) (serializeNested(elementCodec, elem).length * 8L));
                putElemRange(fi.name, list.size() - 1, before, cursor.bitOffset());
            }
            return list;
        } else {
            // BYTES/String:逐字节读到标记
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            while (true) {
                if (atSentinelMarker(fi, cursor)) {
                    cursor.skipBits(8 * fi.sentinelByteLen());  // 消费标记
                    break;
                }
                if (cursor.peekByte() < 0) {
                    throw new IllegalStateException(
                            "sentinel field " + fi.name + ": reached end of data without marker");
                }
                bos.write((int) cursor.readBits(8));  // 读一字节(取低8位)
            }
            if (fi.field.getType() == String.class) {
                return new String(bos.toByteArray(), Charset.forName(fi.charset));
            }
            return bos.toByteArray();
        }
    }

    /** 游标当前位置是否命中终结标记(单/多字节);命中不消费。 */
    private boolean atSentinelMarker(FieldInfo fi, BitCursor cursor) {
        if (fi.sentinelBytes.length > 0) {
            byte[] peek = cursor.peekBytes(fi.sentinelBytes.length);
            return peek != null && java.util.Arrays.equals(peek, fi.sentinelBytes);
        }
        return cursor.peekByte() == fi.sentinel;
    }

    private void writeValue(FieldInfo fi, Object obj, BitCursor cursor, int size, FieldContext ctx) throws Exception {
        // sentinel 序列化:写数据 + 追加标记字节
        if (fi.hasSentinel()) {
            writeSentinelValue(fi, obj, cursor);
            return;
        }
        // LIST_TLV 序列化:每个元素 type+length+value,末尾 sentinel
        if (effectiveType(fi) == FieldType.LIST_TLV) {
            writeTlvValue(fi, obj, cursor);
            return;
        }
        FieldType type = effectiveType(fi);
        fi.field.setAccessible(true);
        Object value = fi.field.get(obj);
        switch (type) {
            case INT, UNSIGNED -> {
                long v = convertFromFieldType(value);
                if (fi.endian == com.netproto.annotation.Endian.LITTLE) {
                    v = reverseBytes(v, size / 8);
                }
                cursor.writeBits(v, size);
            }
            case FLOAT -> {
                if (size == 32) {
                    cursor.writeBits(Float.floatToIntBits(((Number) value).floatValue()), 32);
                } else {
                    cursor.writeBits(Double.doubleToLongBits(((Number) value).doubleValue()), 64);
                }
            }
            case BCD -> {
                long v = convertFromFieldType(value);
                long out = 0;
                for (int i = 0; i < size / 4; i++) {
                    out |= (v % 10) << (4 * i);
                    v /= 10;
                }
                cursor.writeBits(out, size);
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
                ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
                if (!fi.sentinelOn.isEmpty()) {
                    // 元素内 sentinel:写元素 + 末尾追加 sentinelValue
                    for (Object elem : list) {
                        cursor.writeBytes(serializeNested(elementCodec, elem));
                    }
                    cursor.writeBits(fi.sentinelValue, fi.sentinelOnSize);
                } else {
                    // count 驱动时校验个数一致(回填在第一遍 listTotalBits 已完成);
                    // declared<0 = null 数组语义(如 Kafka topicsCount=-1):跳过校验,写空列表
                    if (!fi.countField.isEmpty()) {
                        boolean byBytes = fi.countUnit == com.netproto.annotation.CountUnit.BYTES;
                        java.lang.reflect.Field cf = findFieldByName(obj.getClass(), fi.countField);
                        long declared = numberFieldValue(cf, obj);
                        if (declared >= 0) {
                            long expected = byBytes
                                    ? list.size() * (fixedBitSize(fi.elementClass) / 8)
                                    : list.size();
                            if (declared != expected) {
                                throw new IllegalStateException(
                                        "LIST field '" + fi.name + "': countField '" + fi.countField
                                                + "'=" + declared + " but " + (byBytes ? "bytes" : "count")
                                                + "=" + expected);
                            }
                        }
                    }
                    for (Object elem : list) {
                        cursor.writeBytes(serializeNested(elementCodec, elem));
                    }
                }
            }
        }
    }

    /** sentinel 序列化:写数据 + 追加标记字节。 */
    private void writeSentinelValue(FieldInfo fi, Object obj, BitCursor cursor) throws Exception {
        fi.field.setAccessible(true);
        Object value = fi.field.get(obj);
        if (value == null) {
            // 空数据:仅写标记字节
        } else if (value instanceof String s) {
            cursor.writeBytes(s.getBytes(Charset.forName(fi.charset)));
        } else if (value instanceof byte[] bytes) {
            cursor.writeBytes(bytes);
        } else if (value instanceof java.util.List<?> list) {
            ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
            for (Object elem : list) {
                cursor.writeBytes(serializeNested(elementCodec, elem));
            }
        } else {
            throw new IllegalStateException("sentinel field " + fi.name + " must be String/byte[]/List");
        }
        if (fi.sentinelBytes.length > 0) {
            cursor.writeBytes(fi.sentinelBytes);          // 多字节标记
        } else {
            cursor.writeBits(fi.sentinel, 8);             // 单字节标记
        }
    }

    /** LIST_TLV 序列化:每个元素 type+length+value,末尾追加 sentinel。 */
    @SuppressWarnings("unchecked")
    private void writeTlvValue(FieldInfo fi, Object obj, BitCursor cursor) throws Exception {
        fi.field.setAccessible(true);
        java.util.List<Object> list = (java.util.List<Object>) fi.field.get(obj);
        for (Object elem : list) {
            Integer type = fi.reverseDispatchMap.get(elem.getClass().getSimpleName());
            if (type == null) {
                throw new IllegalStateException(
                        "TLV element " + elem.getClass().getName() + " not in dispatch table");
            }
            byte[] valueBytes = serializeNested(codecFor(elem.getClass()), elem);
            cursor.writeBits(type, 8);
            cursor.writeBits(valueBytes.length, 8);
            cursor.writeBytes(valueBytes);
        }
        if (fi.tlvEndMarker >= 0) {
            cursor.writeBits(fi.tlvEndMarker, 8);
        }
    }

    private FieldType effectiveType(FieldInfo fi) {
        if (fi.type != FieldType.INT) {
            return fi.type; // 显式指定
        }
        // INT 默认:按 Java 类型推断(BYTES/STRING/NESTED/LIST)
        Class<?> t = fi.field.getType();
        if (t == float.class || t == Float.class || t == double.class || t == Double.class) {
            return FieldType.FLOAT;
        }
        if (java.util.List.class.isAssignableFrom(t)) {
            return FieldType.LIST;
        }
        if (t == byte[].class) {
            return FieldType.BYTES;
        }
        if (t == String.class) {
            return FieldType.STRING;
        }
        // 字段类型本身是 @Protocol 实体 → 当作 NESTED(也可显式 type=NESTED)
        if (!t.isPrimitive() && !Number.class.isAssignableFrom(t)
                && t.isAnnotationPresent(com.netproto.annotation.Protocol.class)) {
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

    /** 解析 dispatch 类名:简单名按 declaringClass 所在包,全限定名直接加载。 */
    private static Class<?> resolveDispatchClass(String className, Class<?> contextClass) {
        if (className.contains(".")) {
            try { return Class.forName(className); } catch (ClassNotFoundException e) {
                throw new IllegalArgumentException("dispatch class not found: " + className, e);
            }
        }
        String pkg = contextClass.getPackageName();
        String fqn = pkg.isEmpty() ? className : pkg + "." + className;
        try { return Class.forName(fqn); } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("dispatch class not found: " + className + " (resolved " + fqn + ")", e);
        }
    }

    /**
     * 序列化嵌套实体。{@code ProtocolCodec<?>} 的 T 是通配符捕获,无法直接接受 Object,
     * 故以 raw 类型绕过泛型(嵌套实体的类型已由字段声明保证一致)。
     */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static byte[] serializeNested(ProtocolCodec<?> codec, Object value) {
        return ((ProtocolCodec) codec).serialize(value);
    }

    private static Object convertToFieldType(Class<?> type, long val, boolean unsigned, Class<?> enumClass, Class<?> flagClass) {
        // enum 字段:优先用注解的 enumClass,否则用字段 type(若它本身就是具体 enum)
        Class<?> effectiveEnumType = (enumClass != null && enumClass != void.class) ? enumClass : type;
        if (ProtocolEnum.class.isAssignableFrom(effectiveEnumType) && Enum.class.isAssignableFrom(effectiveEnumType)) {
            return enumFromValue(effectiveEnumType, (int) val);
        }
        // flag 字段:Set<ProtocolFlag>,按位拆解成 EnumSet(保留位忽略)
        if (flagClass != null && flagClass != void.class && java.util.Set.class.isAssignableFrom(type)) {
            return flagsFromValue(flagClass, (int) val);
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

    /** 把整数按位拆解成 EnumSet;保留位(flagClass 未覆盖的位)忽略(C1)。 */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static Object flagsFromValue(Class<?> flagClass, int value) {
        Object[] constants = flagClass.getEnumConstants();
        java.util.EnumSet result = java.util.EnumSet.noneOf((Class<Enum>) flagClass);
        if (constants != null) {
            for (Object c : constants) {
                if (((ProtocolFlag) c).mask() != 0 && (value & ((ProtocolFlag) c).mask()) != 0) {
                    result.add(c);
                }
            }
        }
        return result;
    }

    private static long convertFromFieldType(Object value) {
        if (value instanceof ProtocolEnum e) {
            return e.value();
        }
        // flag 字段:Set<ProtocolFlag> → 各 mask 按位 OR
        if (value instanceof java.util.Set<?> set) {
            long orResult = 0;
            for (Object o : set) {
                if (o instanceof ProtocolFlag f) {
                    orResult |= f.mask();
                }
            }
            return orResult;
        }
        if (value == null) {
            return 0;
        }
        if (value instanceof Number n) {
            return n.longValue();
        }
        return 0;
    }

    // ---- 内部结构 ----
    private static final class FieldInfo {
        final Field field;
        final String name;
        final int order;
        final int size;
        final com.netproto.annotation.Endian endian;
        final FieldType type;
        final String lengthField;
        final LengthUnit lengthUnit;
        final String presentIf;
        final String charset;
        final String countField;
        final Class<?> elementClass;
        final int lengthAdjust;
        final int sentinel;
        final String sentinelOn;
        final long sentinelValue;
        final int sentinelOnSize;
        final byte[] sentinelBytes;   // 多字节终结符(空数组=未用)
        final com.netproto.annotation.CountUnit countUnit;
        final boolean lengthAscii;
        final Class<?> enumClass;
        final Class<?> flagClass;
        final int tlvEndMarker;
        final String[] dispatch;
        final java.util.Map<Integer,String> dispatchMap;
        final java.util.Map<String,Integer> reverseDispatchMap;
        final boolean checksumField;
        final boolean untilEnd;
        final FieldCodec<Object> custom;
        final Expr.Node presentIfNode;

        /** 是否启用终结标记(单字节 sentinel 或多字节 sentinelStr)。 */
        boolean hasSentinel() {
            return sentinel >= 0 || sentinelBytes.length > 0;
        }

        /** 终结标记的字节数。 */
        int sentinelByteLen() {
            return sentinelBytes.length > 0 ? sentinelBytes.length : 1;
        }

        /** 常规字段构造:读取 @ProtocolField 的全部属性。 */
        FieldInfo(Field f) {
            this.field = f;
            this.name = f.getName();
            com.netproto.annotation.ProtocolField ann = f.getAnnotation(com.netproto.annotation.ProtocolField.class);
            this.order = ann.order();
            this.size = ann.size();
            this.endian = ann.endian();
            if (this.endian == com.netproto.annotation.Endian.LITTLE
                    && (this.size <= 0 || this.size % 8 != 0)) {
                throw new IllegalArgumentException(
                        "field '" + this.name + "' LITTLE endian requires a fixed size in whole bytes");
            }
            this.type = ann.type();
            this.lengthField = ann.lengthField();
            this.lengthUnit = ann.lengthUnit();
            this.presentIf = ann.presentIf();
            this.charset = ann.charset();
            this.countField = ann.countField();
            this.elementClass = ann.elementClass();
            this.lengthAdjust = ann.lengthAdjust();
            this.sentinel = ann.sentinel();
            this.sentinelOn = ann.sentinelOn();
            this.countUnit = ann.countUnit();
            this.lengthAscii = ann.lengthAscii();
            String sstr = ann.sentinelStr();
            if (!sstr.isEmpty() && this.sentinel >= 0) {
                throw new IllegalArgumentException(
                        "field '" + this.name + "': sentinel and sentinelStr are mutually exclusive");
            }
            this.sentinelBytes = sstr.isEmpty()
                    ? new byte[0]
                    : sstr.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            this.sentinelValue = ann.sentinelValue();
            if (!this.sentinelOn.isEmpty()) {
                if (this.elementClass == void.class) {
                    throw new IllegalArgumentException(
                            "field '" + this.name + "' sentinelOn requires elementClass");
                }
                this.sentinelOnSize = lookupSentinelOnSize(this.elementClass, this.sentinelOn);
            } else {
                this.sentinelOnSize = 0;
            }
            this.enumClass = ann.enumClass();
            this.flagClass = ann.flagClass();
            this.tlvEndMarker = ann.tlvEndMarker();
            this.dispatch = ann.dispatch();
            // 解析 dispatch 为正/反向 Map
            // 正向:type → 类名字符串(反序列化用 resolveDispatchClass 加载)
            // 反向:类简单名 → type(序列化用 elem.getClass().getSimpleName() 反查)
            java.util.Map<Integer,String> fwd = new java.util.HashMap<>();
            java.util.Map<String,Integer> rev = new java.util.HashMap<>();
            for (String entry : this.dispatch) {
                int eq = entry.indexOf('=');
                if (eq < 0) throw new IllegalArgumentException("dispatch entry must be 'type=ClassName': " + entry);
                int t = Integer.parseInt(entry.substring(0, eq).trim());
                String cn = entry.substring(eq + 1).trim();
                if (fwd.containsKey(t)) throw new IllegalArgumentException("dispatch type " + t + " duplicated");
                fwd.put(t, cn);
                String simple = cn.contains(".") ? cn.substring(cn.lastIndexOf('.') + 1) : cn;
                rev.put(simple, t);
            }
            this.dispatchMap = fwd;
            this.reverseDispatchMap = rev;
            this.checksumField = f.isAnnotationPresent(com.netproto.annotation.ChecksumField.class);
            this.untilEnd = ann.untilEnd();
            // L2 逃生舱:实例化自定义编解码器(须有无参构造)
            if (ann.custom() != void.class) {
                try {
                    java.lang.reflect.Constructor<?> fc = ann.custom().getDeclaredConstructor();
                    fc.setAccessible(true);
                    @SuppressWarnings("unchecked")
                    FieldCodec<Object> c = (FieldCodec<Object>) fc.newInstance();
                    this.custom = c;
                } catch (Exception e) {
                    throw new IllegalArgumentException(
                            "cannot instantiate custom codec " + ann.custom().getName()
                                    + " for field '" + this.name + "' (needs public no-arg ctor)", e);
                }
            } else {
                this.custom = null;
            }
            // presentIf 预编译(语法错误在 codec 构建期暴露)
            this.presentIfNode = this.presentIf.isBlank() ? null : Expr.compile(this.presentIf);
            // 校验:dispatch 类必须存在且是 @Protocol 实体
            Class<?> ctx = f.getDeclaringClass();
            for (String cn : fwd.values()) {
                Class<?> c = resolveDispatchClass(cn, ctx);
                if (!c.isAnnotationPresent(com.netproto.annotation.Protocol.class)) {
                    throw new IllegalArgumentException(
                            "dispatch class " + cn + " is not a @Protocol entity");
                }
            }
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
            this.sentinelOn = "";
            this.sentinelValue = 0;
            this.sentinelOnSize = 0;
            this.sentinelBytes = new byte[0];
            this.countUnit = com.netproto.annotation.CountUnit.ELEMENTS;
            this.lengthAscii = false;
            this.endian = com.netproto.annotation.Endian.BIG;
            this.enumClass = void.class;
            this.flagClass = void.class;
            this.tlvEndMarker = -1;
            this.dispatch = new String[0];
            this.dispatchMap = java.util.Collections.emptyMap();
            this.reverseDispatchMap = java.util.Collections.emptyMap();
            this.checksumField = false;
            this.untilEnd = false;
            this.custom = null;
            this.presentIfNode = null;
        }
    }

    // ---- PacketCodec SPI(新架构入口,旧 deserialize/serialize 保留兼容) ----

    @Override
    public T decode(byte[] data, int offset, int length) {
        return deserialize(data, offset, length);
    }

    @Override
    public byte[] encode(T packet) {
        return serialize(packet);
    }

    @Override
    public int headerBytes() {
        return (lastHeaderBits + 7) / 8;
    }

    @Override
    public java.util.Map<String, int[]> lastFieldRanges() {
        return java.util.Collections.unmodifiableMap(lastFieldRanges);
    }
}
