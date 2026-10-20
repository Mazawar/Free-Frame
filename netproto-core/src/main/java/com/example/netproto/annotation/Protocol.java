package com.example.netproto.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标记一个协议报文类(替代旧 @ProtocolPacket)。
 * <p>
 * 协议之间的层级关系由 {@link BindOn} 声明;不带 BindOn 的是「孤岛协议」,
 * 不参与自顶向下分派,但仍可作 NESTED/LIST 元素或被直接编码。
 * <p>
 * {@code codec} 是报文级逃生舱(L3):指定后整个协议的编解码交给手写实现,
 * 反射式引擎不再参与,但该协议仍通过 @BindOn 挂回分派树。
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface Protocol {

    /** 协议 id:分派树节点名,全局唯一。 */
    String id();

    /** 显示名(空则取 id)。 */
    String name() default "";

    /** 内置协议标记(仅 UI 徽标语义,不影响分派)。 */
    boolean builtin() default false;

    /** 协议分组名(仅 UI 归纳语义):同组协议在侧栏折叠到一块,如 "Modbus"/"S7comm"。 */
    String group() default "";

    /** 报文级编解码器(必须实现 PacketCodec 且有无参构造);void.class = 反射式默认。 */
    Class<?> codec() default void.class;
}
