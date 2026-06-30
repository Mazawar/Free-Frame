package com.example.demo.protocol.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标记校验和字段。序列化时引擎在该位置置 0 → 调 compute → 回写。实体须实现 Checksum。 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ChecksumField {
}
