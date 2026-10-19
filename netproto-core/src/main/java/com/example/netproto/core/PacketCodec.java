package com.example.netproto.core;

/**
 * 报文级编解码契约(L3 逃生舱)。
 * <p>
 * 反射式默认实现是 {@link ProtocolCodec};用户可在 @Protocol(codec=X.class)
 * 里提供手写实现完全接管一个协议的编解码,仍通过 @BindOn 挂回分派树。
 */
public interface PacketCodec<T> {

    /** 解析:从 data[offset, offset+length) 读出一个报文。失败抛 RuntimeException。 */
    T decode(byte[] data, int offset, int length);

    /** 组装:两遍式(先算总位宽,再写入,最后回写计算字段)。 */
    byte[] encode(T packet);

    /**
     * 最近一次 decode 中「头部」消费的字节数(payload 之前的字节数)。
     * 分派引擎用它确定子层起始偏移。-1 表示不支持子层分派(该层视为叶子)。
     */
    int headerBytes();
}
