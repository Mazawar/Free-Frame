package com.example.demo.protocol.core;

/** 位标志契约:实现此接口的 enum 可作为 @ProtocolField(flagClass=...) 的 flag 字段。 */
public interface ProtocolFlag {

    /** 该 flag 常量对应的位掩码(单 bit,如 SYN=0x02)。 */
    int mask();
}
