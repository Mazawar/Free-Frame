package com.example.demo.protocol.annotation;

import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.LengthUnit;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ProtocolField {

    /** 字段排列顺序(必填)。 */
    int order();

    /** 位数(取消「8 的倍数」限制)。 */
    int size() default -1;

    /** 值类型,默认由 Java 字段类型推断。 */
    FieldType type() default FieldType.INT;

    /** 变长字段:长度引用某字段名(声明式)。 */
    String lengthField() default "";

    /** lengthField 值的单位。 */
    LengthUnit lengthUnit() default LengthUnit.BYTES;

    /** length 偏移:字段字节长度 = lengthField值 + lengthAdjust。默认 0(纯引用,Phase 1 行为不变)。 */
    int lengthAdjust() default 0;

    /** 条件字段:"field==值" 满足才出现。 */
    String presentIf() default "";

    /** STRING 类型字符集。 */
    String charset() default "UTF-8";

    /** count 驱动(LIST 用):引用元素个数字段名。 */
    String countField() default "";

    /** LIST 元素的实体类型(LIST 时必填)。 */
    Class<?> elementClass() default void.class;

    /** sentinel 结束标记字节值(0x00–0xFF);-1 表示不用。读到该字节就结束。与 countField/lengthField 互斥。 */
    int sentinel() default -1;

    /** 枚举字段:字段声明为 ProtocolEnum 接口类型时,用此指定具体 enum 类(扫描其常量)。 */
    Class<?> enumClass() default void.class;
}
