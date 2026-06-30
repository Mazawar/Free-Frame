package com.example.demo.protocol.core;

/** 校验和钩子:实体可选实现,提供校验和计算逻辑。 */
public interface Checksum {

    /**
     * 计算校验和字段的值。
     *
     * @param fieldName  哪个字段要算校验和(@ChecksumField 标记的字段名)
     * @param serialized 整个实体序列化后的字节(校验和字段已被引擎置 0)
     * @return 校验和值;返回 -1 表示不接管该字段(走普通路径)
     */
    long compute(String fieldName, byte[] serialized);
}
