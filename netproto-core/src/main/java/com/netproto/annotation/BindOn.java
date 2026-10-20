package com.netproto.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 声明本协议挂载到哪个父协议、命中条件是什么(分派规则)。
 * <p>
 * {@code when} 表达式只能引用父协议的 @ProtocolField 字段名,支持
 * {@code == != < <= > >= && || ! ( )} 与十进制/0x 字面量。
 * 父字段因条件缺席而未解析时,表达式按 false 处理(不抛异常)。
 * <p>
 * 可重复:同一协议可挂多个父(如同时挂 ipv4/ipv6)。
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(BindOn.Container.class)
public @interface BindOn {

    /** 父协议 id。 */
    String parent();

    /** 命中条件表达式,如 "dstPort == 9999 || srcPort == 9999"。 */
    String when();

    /** 同父多绑定同时命中时,高者优先;平级取注册顺序(启动告警)。 */
    int priority() default 0;

    /** 可重复容器。 */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @interface Container {
        BindOn[] value();
    }
}
