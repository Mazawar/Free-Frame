package com.example.demo.protocol.core;

/**
 * 钩子接口:为算术复杂/多字段联动的长度提供类型安全逃生舱。
 * 实体类可选实现;不实现则该字段走声明式(lengthField/size)。
 */
public interface DynamicSize {

    /**
     * 计算指定字段的位长度。
     *
     * @param fieldName 字段名
     * @param ctx 已解析字段视图
     * @return 该字段的 bit 数;返回 -1 表示「交还声明式」
     */
    long computeSize(String fieldName, FieldContext ctx);
}
