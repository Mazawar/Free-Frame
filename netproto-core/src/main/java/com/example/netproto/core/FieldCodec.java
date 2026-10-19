package com.example.netproto.core;

/**
 * 字段级自定义编解码契约(L2 逃生舱)。
 * <p>
 * 一个字段太怪(LEB128 varint、带压缩指针的 DNS 名、offset 定位……)时,
 * 用 @ProtocolField(custom=X.class) 接管该字段的读写,其余字段仍为声明式。
 * 实现类必须有无参构造,实例在 codec 构建期创建并复用(须无状态或线程安全)。
 */
public interface FieldCodec<T> {

    /**
     * 从游标当前位置读出字段值(自行推进游标)。
     *
     * @param cursor        位级读写游标(MSB 优先,大端)
     * @param ctx           本报文已解析字段的只读视图(动态行为数据来源)
     * @param remainingBytes 从当前字节位置到本层末尾的剩余字节数(游标须字节对齐时有效)
     */
    T read(BitCursor cursor, FieldContext ctx, int remainingBytes);

    /** 把 value 写到游标当前位置(自行推进游标)。 */
    void write(BitCursor cursor, FieldContext ctx, T value);

    /** value 序列化后的位宽(两遍式序列化第一遍与总位宽计算用)。 */
    long sizeOf(T value);
}
