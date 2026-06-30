package com.example.demo.protocol.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 反/序列化过程中「已解析字段」的只读视图,动态行为(长度引用、条件、钩子)的唯一数据来源。
 * 反序列化时字段「解析完才入 ctx」,引用者只能看到先于自己解析完的字段。
 *
 * 注:put 暴露在接口上仅为方便 codec 内部写入(由 CodecImpl 持有并调用);
 * 对外语义上仍是只读——动态行为代码只应调用 getInt/get/hasRead。
 */
public interface FieldContext {

    /** 取字段的 int 语义值。不存在或未解析 → 抛 IllegalArgumentException。 */
    int getInt(String fieldName);

    /** 取原始对象值(字符串/字节/嵌套实体等)。 */
    Object get(String fieldName);

    /** 该字段是否已解析。 */
    boolean hasRead(String fieldName);

    /** 绑定的实体对象(钩子做多字段联动时用)。 */
    Object entity();

    /**
     * 写入字段值。仅供 codec 内部调用(解析完一个字段后入 ctx)。
     * 暴露在接口上是为了让 codec 通过 FieldContext 引用直接写入。
     */
    void put(String name, Object value);

    /** 工厂:无实体绑定。 */
    static FieldContext create() {
        return new Impl(null);
    }

    /** 工厂:绑定实体。 */
    static FieldContext create(Object entity) {
        return new Impl(entity);
    }

    /** 可变实现(仅供 codec 内部 put;对外通过接口暴露只读方法)。 */
    final class Impl implements FieldContext {
        private final Map<String, Object> values = new LinkedHashMap<>();
        private final Object entity;

        Impl(Object entity) {
            this.entity = entity;
        }

        @Override
        public void put(String name, Object value) {
            values.put(name, value);
        }

        @Override
        public int getInt(String fieldName) {
            Object v = values.get(fieldName);
            if (v == null) {
                throw new IllegalArgumentException("field not read yet: " + fieldName);
            }
            if (v instanceof Number n) {
                return n.intValue();
            }
            throw new IllegalArgumentException("field is not numeric: " + fieldName);
        }

        @Override
        public Object get(String fieldName) {
            if (!values.containsKey(fieldName)) {
                throw new IllegalArgumentException("field not read yet: " + fieldName);
            }
            return values.get(fieldName);
        }

        @Override
        public boolean hasRead(String fieldName) {
            return values.containsKey(fieldName);
        }

        @Override
        public Object entity() {
            return entity;
        }
    }
}
