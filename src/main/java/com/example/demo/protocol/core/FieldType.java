package com.example.demo.protocol.core;

/** 字段值类型,决定 Java 值 ↔ bit 序列如何转换。 */
public enum FieldType {
    /** 整数(byte/short/int/long),带符号按 Java 类型。 */
    INT,
    /** 无符号整数(size ≤ 63)。 */
    UNSIGNED,
    /** 原始字节 byte[]。 */
    BYTES,
    /** 文本 String,配 charset。 */
    STRING,
    /** 协议嵌套:字段是另一个实体类,递归编解码。 */
    NESTED,
    /** count 驱动的同质重复数组:元素是 elementClass 实体,个数由 countField 决定。 */
    LIST
}
