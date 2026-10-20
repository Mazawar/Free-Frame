package com.netproto.annotation;

/** countField 的单位。 */
public enum CountUnit {
    /** 计数字段值 = 元素个数(默认)。 */
    ELEMENTS,
    /** 计数字段值 = 字节数(元素须定长,个数 = ceil(字节/元素字节),如 Modbus byteCount)。 */
    BYTES
}
