package com.example.demo.protocol.core;

/** 枚举字段契约:实现此接口的 enum 可作为 @ProtocolField 字段类型。 */
public interface ProtocolEnum {

    /** 该枚举常量对应的整数值(协议里的 wire 值)。 */
    int value();
}
