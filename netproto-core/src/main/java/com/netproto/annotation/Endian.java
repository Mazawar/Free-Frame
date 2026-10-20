package com.netproto.annotation;

/** 整数字段字节序。LITTLE 仅支持 8 位倍数的定长整数字段(位字段无字节序)。 */
public enum Endian {
    BIG,
    LITTLE
}
