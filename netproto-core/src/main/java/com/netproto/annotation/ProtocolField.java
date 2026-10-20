package com.netproto.annotation;

import com.netproto.core.FieldType;
import com.netproto.core.LengthUnit;

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

    /** 整数字段字节序(默认大端/网络序)。LITTLE 要求 size 为 8 的倍数。 */
    Endian endian() default Endian.BIG;

    /** 值类型,默认由 Java 字段类型推断。 */
    FieldType type() default FieldType.INT;

    /** 变长字段:长度引用某字段名(声明式)。 */
    String lengthField() default "";

    /** lengthField 值的单位。 */
    LengthUnit lengthUnit() default LengthUnit.BYTES;

    /** length 偏移:字段字节长度 = lengthField值 + lengthAdjust。默认 0(纯引用,Phase 1 行为不变)。 */
    int lengthAdjust() default 0;

    /** lengthField 引用字段的值是 ASCII 十进制文本(如 LLVAR 两位 "12")时置 true。 */
    boolean lengthAscii() default false;

    /** 条件字段:"field==值" 满足才出现。 */
    String presentIf() default "";

    /** STRING 类型字符集。 */
    String charset() default "UTF-8";

    /** count 驱动(LIST 用):引用元素个数字段名。 */
    String countField() default "";

    /** countField 值的单位:BYTES 时元素须定长(如 Modbus byteCount,个数=字节/元素字节)。 */
    CountUnit countUnit() default CountUnit.ELEMENTS;

    /** LIST 元素的实体类型(LIST 时必填)。 */
    Class<?> elementClass() default void.class;

    /** sentinel 结束标记字节值(0x00–0xFF);-1 表示不用。读到该字节就结束。与 countField/lengthField 互斥。 */
    int sentinel() default -1;

    /** 多字节终结符(如 "\\r\\n");与 sentinel 单字节互斥,二者取一。 */
    String sentinelStr() default "";

    /** LIST 元素内 sentinel:元素里哪个字段判定终止(peek 该字段值)。与 countField/sentinel 互斥。 */
    String sentinelOn() default "";

    /** sentinelOn 字段==此值则终止 LIST。 */
    long sentinelValue() default 0;

    /** 枚举字段:字段声明为 ProtocolEnum 接口类型时,用此指定具体 enum 类(扫描其常量)。 */
    Class<?> enumClass() default void.class;

    /** 位标志字段:字段类型为 Set,用此指定具体 flag enum 类。 */
    Class<?> flagClass() default void.class;

    /** 异质 TLV 的 sentinel:type == 此值就结束(0x00–0xFF);-1 表示不用(读到末尾停)。 */
    int tlvEndMarker() default -1;

    /** 异质 TLV 分派表:type→value 实体类名,格式 {"1=SubnetMask", "3=Router"}。
     *  类名为简单名时按字段声明类所在包解析;也支持全限定名。 */
    String[] dispatch() default {};

    /** LIST 循环·耗尽驱动:读到缓冲区末尾为止(元素须自定边界)。
     *  与 countField/sentinel/sentinelOn/lengthField 互斥。 */
    boolean untilEnd() default false;

    /** 字段级逃生舱(L2):自定义编解码器(必须实现 FieldCodec 且有无参构造)。
     *  指定后该字段的读写/尺寸完全由其接管,与 size/lengthField 互斥。 */
    Class<?> custom() default void.class;

    /** 展示分组名(Wireshark 式命名组,如 "Flags"/"Connect Flags"):同组字段在观测页折叠为
     *  一个带名父节点。约束(注册期校验):同组字段按 order 相邻,位宽总和按字节对齐。 */
    String group() default "";

    /** 展示名(Wireshark 式字段名,如 "Time To Live");空 = 用字段名。只影响展示,不影响绑定/过滤。 */
    String label() default "";
}
