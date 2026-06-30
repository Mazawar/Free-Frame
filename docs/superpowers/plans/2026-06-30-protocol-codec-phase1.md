# 通用协议编解码引擎 Phase 1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `ProtocolCodec` 从「固定字节对齐 + 末尾单 payload」升级为「位级 + 声明式长度引用 + 钩子 + 嵌套 + 条件字段」的通用引擎,并用真实 IPv4 包的 pcap4j parity 验收。

**Architecture:** 以「位游标 BitCursor」替代字节偏移做位级读写;以「FieldContext 只读视图」承载动态行为的数据来源;长度/条件优先走声明式注解(`lengthField`/`presentIf`),算术等复杂场景走类型安全钩子(`DynamicSize`)。每字段解析顺序固定,反序列化逐字段填入 ctx,序列化对称。

**Tech Stack:** Java 25,Spring Boot 4.1,pcap4j 1.8.2(解析器对照基准),JUnit Jupiter 6 + AssertJ 3.27 + Mockito,Lombok。

**参考 spec:** `docs/superpowers/specs/2026-06-30-protocol-codec-phase1-design.md`

---

## 文件结构

新增/修改文件一览(包路径 `com.example.demo.protocol.*`):

| 文件 | 责任 | 动作 |
|---|---|---|
| `core/BitCursor.java` | 位级读写游标:MSB 优先、网络序大端、跨字节 | 新建 |
| `core/FieldContext.java` | 反/序列化中已解析字段的只读视图 | 新建 |
| `core/DynamicSize.java` | 钩子接口:算术复杂长度 | 新建 |
| `core/FieldType.java` | 字段值类型枚举(INT/UNSIGNED/BYTES/STRING/NESTED) | 新建 |
| `core/LengthUnit.java` | 长度单位枚举(BYTES/BITS) | 新建 |
| `annotation/ProtocolField.java` | 扩展注解(size 取消限制 + type/lengthField/lengthUnit/presentIf/charset) | 修改 |
| `core/ProtocolCodec.java` | 重构编解码主逻辑(位游标 + ctx + NESTED + 条件 + 钩子) | 修改 |
| `protocol/Ipv4Header.java` | 验收标本实体(IPv4 头 + options 钩子) | 新建 |
| `protocol/EthernetFrame.java` | 嵌套验收实体(外层套 Ipv4Header) | 新建 |
| `test/.../BitCursorTest.java` | 位级读写单测 | 新建 |
| `test/.../CodecBitFieldTest.java` | 位字段编解码(含 6+2、3+13 跨字节) | 新建 |
| `test/.../CodecLengthRefTest.java` | 声明式 lengthField 长度引用 | 新建 |
| `test/.../CodecConditionalTest.java` | presentIf 条件字段 | 新建 |
| `test/.../CodecNestedTest.java` | NESTED 协议嵌套 | 新建 |
| `test/.../CodecRegistryValidationTest.java` | 注册期不变式(前向引用/字段不存在) | 新建 |
| `test/.../MyProtocolRegressionTest.java` | 老协议零改动回归 | 新建 |
| `test/.../Ipv4ParityTest.java` | 真实 IPv4 包 vs pcap4j 逐字段 parity | 新建 |
| `test/resources/ipv4-sample.pcap` | 真实抓包样本(程序生成) | 新建 |

**测试约定:** 命令统一 `./mvnw -q test`(全量)或 `./mvnw -q test -Dtest=XxxTest`(单类)。所有测试为纯 JUnit,无 Spring 上下文依赖。

---

## Task 1: BitCursor 位级读写游标

**Files:**
- Create: `src/main/java/com/example/demo/protocol/core/BitCursor.java`
- Test: `src/test/java/com/example/demo/protocol/core/BitCursorTest.java`

- [ ] **Step 1: 写失败测试**

`src/test/java/com/example/demo/protocol/core/BitCursorTest.java`:
```java
package com.example.demo.protocol.core;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class BitCursorTest {

    @Test
    void readsBitFieldInSameByteMsbFirst() {
        // byte0 = 0x45 -> 高4位=0x4(version), 低4位=0x5(ihl)
        byte[] data = {0x45};
        BitCursor c = new BitCursor(data, 0);
        assertThat(c.readBits(4)).isEqualTo(0x4L);
        assertThat(c.readBits(4)).isEqualTo(0x5L);
        assertThat(c.bitOffset()).isEqualTo(8);
    }

    @Test
    void readsCrossByteBigEndian() {
        // 13-bit 字段跨越字节: byte0 高3位(忽略,未读)+ byte0低5位 + byte1全8位
        // 构造: byte0=0x09 (00001001) -> 低5位=01001=0x09 ; byte1=0x23
        // 读13位 = byte0低5位(0x09) << 8 | byte1(0x23) = 0x0923
        byte[] data = {(byte) 0b00001_001, (byte) 0b00100011 /* 0x23 */};
        BitCursor c = new BitCursor(data, 0);
        long v = c.readBits(13);
        assertThat(c.bitOffset()).isEqualTo(13);
        assertThat(v).isEqualTo((((long) (data[0] & 0xFF) & 0x1F) << 8) | (data[1] & 0xFF));
    }

    @Test
    void writesBitFieldMsbFirst() {
        BitCursor c = new BitCursor(1); // 1 byte
        c.writeBits(0x4L, 4);
        c.writeBits(0x5L, 4);
        assertThat(c.bytes()).containsExactly(0x45);
    }

    @Test
    void writesCrossByteField() {
        BitCursor c = new BitCursor(2);
        c.writeBits(0x0123L, 13);
        byte[] out = c.bytes();
        // 0x0123 = 13位 = 00001_0010_0011, 大端铺进 16 位(高3位补0)
        // byte0 高8位 = 00001_001 = 0x09 ; byte1 = 低5位 00011 + 3位补0 = 0001_1000 = 0x18
        assertThat(out[0] & 0xFF).isEqualTo(0b00001_001);  // 0x09
        assertThat(out[1] & 0xFF).isEqualTo(0b00011_000);  // 0x18
    }

    @Test
    void readOffsetStartsAtByteBoundary() {
        byte[] data = {0x12, 0x34};
        BitCursor c = new BitCursor(data, 1); // 从第1字节起
        assertThat(c.readBits(8)).isEqualTo(0x34L);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `./mvnw -q test -Dtest=BitCursorTest`
Expected: 编译失败(BitCursor 不存在)

- [ ] **Step 3: 实现 BitCursor**

`src/main/java/com/example/demo/protocol/core/BitCursor.java`:
```java
package com.example.demo.protocol.core;

/**
 * 位级读写游标。MSB 优先(字节内高位先填)、网络序大端(跨字节)、允许字段跨字节边界。
 */
public final class BitCursor {

    private final byte[] data;   // 读取源 / 写入目标
    private final int baseByte;  // 起始字节偏移
    private int bitPos;          // 相对 baseByte 的位偏移
    private final int totalBits; // 容量(仅写入用;读取不强制)

    /** 读模式:基于现有字节。 */
    public BitCursor(byte[] data, int startByteOffset) {
        this.data = data;
        this.baseByte = startByteOffset;
        this.bitPos = 0;
        this.totalBits = (data.length - startByteOffset) * 8;
    }

    /** 写模式:分配 byteCount 字节。 */
    public BitCursor(int byteCount) {
        this.data = new byte[byteCount];
        this.baseByte = 0;
        this.bitPos = 0;
        this.totalBits = byteCount * 8;
    }

    /** 从当前位偏移读 size 位(大端),并推进游标。 */
    public long readBits(int size) {
        if (size < 0 || size > 63) {
            throw new IllegalArgumentException("size must be 0..63, got " + size);
        }
        long value = 0;
        for (int i = 0; i < size; i++) {
            int absBit = baseByte * 8 + bitPos + i;
            int byteIdx = absBit / 8;
            int bitInByte = 7 - (absBit % 8); // MSB 优先
            value = (value << 1) | ((data[byteIdx] >> bitInByte) & 1);
        }
        bitPos += size;
        return value;
    }

    /** 从当前位偏移读 size 位为字节数组(BYTES/STRING/NESTED 用)。 */
    public byte[] readBytes(int size) {
        if (size % 8 != 0) {
            throw new IllegalArgumentException("byte read needs a multiple of 8 bits, got " + size);
        }
        int n = size / 8;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            int absBit = baseByte * 8 + bitPos + i * 8;
            int byteIdx = absBit / 8;
            out[i] = data[byteIdx];
        }
        bitPos += size;
        return out;
    }

    /** 在当前位偏移写 value 的低 size 位(大端),并推进游标。 */
    public void writeBits(long value, int size) {
        if (size < 0 || size > 63) {
            throw new IllegalArgumentException("size must be 0..63, got " + size);
        }
        for (int i = size - 1; i >= 0; i--) {
            int absBit = baseByte * 8 + bitPos + (size - 1 - i);
            int byteIdx = absBit / 8;
            int bitInByte = 7 - (absBit % 8);
            long bit = (value >> i) & 1L;
            if (bit == 1) {
                data[byteIdx] |= (byte) (1 << bitInByte);
            } else {
                data[byteIdx] &= (byte) ~(1 << bitInByte);
            }
        }
        bitPos += size;
    }

    /** 写入字节(BYTES/STRING/NESTED 用),size 必须是 8 的倍数。 */
    public void writeBytes(byte[] bytes) {
        if (bitPos % 8 != 0) {
            throw new IllegalStateException("writeBytes requires byte-aligned cursor, bitPos=" + bitPos);
        }
        int byteStart = baseByte + bitPos / 8;
        System.arraycopy(bytes, 0, data, byteStart, bytes.length);
        bitPos += bytes.length * 8;
    }

    public int bitOffset() {
        return bitPos;
    }

    public byte[] bytes() {
        return data;
    }
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `./mvnw -q test -Dtest=BitCursorTest`
Expected: PASS(5 个测试全绿)

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/BitCursor.java src/test/java/com/example/demo/protocol/core/BitCursorTest.java
git commit -m "feat(codec): add BitCursor for bit-level MSB/big-endian read/write"
```

---

## Task 2: FieldContext 只读视图

**Files:**
- Create: `src/main/java/com/example/demo/protocol/core/FieldContext.java`

- [ ] **Step 1: 写失败测试**

`src/test/java/com/example/demo/protocol/core/FieldContextTest.java`:
```java
package com.example.demo.protocol.core;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FieldContextTest {

    @Test
    void putAndGetInt() {
        FieldContext ctx = FieldContext.create();
        ctx.put("ihl", 5);
        assertThat(ctx.getInt("ihl")).isEqualTo(5);
        assertThat(ctx.hasRead("ihl")).isTrue();
    }

    @Test
    void getIntOnMissingThrows() {
        FieldContext ctx = FieldContext.create();
        assertThatThrownBy(() -> ctx.getInt("nope"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(ctx.hasRead("nope")).isFalse();
    }

    @Test
    void getReturnsRawObject() {
        FieldContext ctx = FieldContext.create();
        ctx.put("options", new byte[]{1, 2});
        assertThat((byte[]) ctx.get("options")).containsExactly(1, 2);
    }

    @Test
    void entityBinding() {
        Object obj = new Object();
        FieldContext ctx = FieldContext.create(obj);
        assertThat(ctx.entity()).isSameAs(obj);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `./mvnw -q test -Dtest=FieldContextTest`
Expected: 编译失败

- [ ] **Step 3: 实现 FieldContext**

`src/main/java/com/example/demo/protocol/core/FieldContext.java`:
```java
package com.example.demo.protocol.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 反/序列化过程中「已解析字段」的只读视图,动态行为(长度引用、条件、钩子)的唯一数据来源。
 * 反序列化时字段「解析完才入 ctx」,引用者只能看到先于自己解析完的字段。
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
```

- [ ] **Step 4: 运行测试确认通过**

Run: `./mvnw -q test -Dtest=FieldContextTest`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/FieldContext.java src/test/java/com/example/demo/protocol/core/FieldContextTest.java
git commit -m "feat(codec): add FieldContext read-only view for dynamic behavior"
```

---

## Task 3: FieldType / LengthUnit 枚举 + DynamicSize 钩子

**Files:**
- Create: `src/main/java/com/example/demo/protocol/core/FieldType.java`
- Create: `src/main/java/com/example/demo/protocol/core/LengthUnit.java`
- Create: `src/main/java/com/example/demo/protocol/core/DynamicSize.java`

这三个是纯定义,无独立测试(由后续 Codec 任务间接覆盖)。

- [ ] **Step 1: 实现三个类型**

`src/main/java/com/example/demo/protocol/core/FieldType.java`:
```java
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
    NESTED
}
```

`src/main/java/com/example/demo/protocol/core/LengthUnit.java`:
```java
package com.example.demo.protocol.core;

/** lengthField 引用值的单位(COUNT 集合语义留 Phase 2)。 */
public enum LengthUnit {
    /** lengthField 值 = 字节数。 */
    BYTES,
    /** lengthField 值 = 位数。 */
    BITS
}
```

`src/main/java/com/example/demo/protocol/core/DynamicSize.java`:
```java
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
```

- [ ] **Step 2: 编译确认**

Run: `./mvnw -q compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/FieldType.java src/main/java/com/example/demo/protocol/core/LengthUnit.java src/main/java/com/example/demo/protocol/core/DynamicSize.java
git commit -m "feat(codec): add FieldType, LengthUnit enums and DynamicSize hook"
```

---

## Task 4: 扩展 @ProtocolField 注解

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/annotation/ProtocolField.java`

- [ ] **Step 1: 扩展注解**

`src/main/java/com/example/demo/protocol/annotation/ProtocolField.java`:
```java
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

    /** 条件字段:"field==值" 满足才出现。 */
    String presentIf() default "";

    /** STRING 类型字符集。 */
    String charset() default "UTF-8";
}
```

- [ ] **Step 2: 编译确认(MyProtocol 仍用旧属性 size,需兼容)**

Run: `./mvnw -q compile`
Expected: BUILD SUCCESS(`size` 有默认值 -1,但 MyProtocol 显式传了 size=8/16/32,仍合法)

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/annotation/ProtocolField.java
git commit -m "feat(codec): extend @ProtocolField with type/lengthField/lengthUnit/presentIf/charset"
```

---

## Task 5: 重构 ProtocolCodec(位游标 + ctx + 类型转换 + NESTED)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`

这是核心。先实现「位字段 + INT/UNSIGNED/BYTES/STRING/NESTED + 固定 size」(先不含 lengthField/presentIf/钩子,留 Task 6/7),保证 TDD 渐进。

- [ ] **Step 1: 写失败测试(位字段 + 跨字节 + NESTED)**

`src/test/java/com/example/demo/protocol/CodecBitFieldTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CodecBitFieldTest {

    @Data
    @ProtocolPacket(port = 7001)
    public static class BitFields {
        @ProtocolField(order = 1, size = 4)  private int version;
        @ProtocolField(order = 2, size = 4)  private int ihl;
        @ProtocolField(order = 3, size = 6)  private int dscp;
        @ProtocolField(order = 4, size = 2)  private int ecn;
        @ProtocolField(order = 5, size = 13) private int fragmentOffset;
        @ProtocolField(order = 6, size = 9)  private int tail; // 凑满 6 字节(4+4+6+2+13+9=38bit... 补到48)
    }

    @Test
    void roundTripsBitFieldsAcrossByteBoundaries() {
        ProtocolCodec<BitFields> codec = new ProtocolCodec<>(BitFields.class);
        BitFields original = new BitFields();
        original.setVersion(0x4);
        original.setIhl(0x5);
        original.setDscp(0x2A);
        original.setEcn(0x1);
        original.setFragmentOffset(0x0123);
        original.setTail(0x1FF); // 9 位全1

        byte[] out = codec.serialize(original);
        // 反过来解析
        BitFields parsed = codec.deserialize(out);

        assertThat(parsed.getVersion()).isEqualTo(0x4);
        assertThat(parsed.getIhl()).isEqualTo(0x5);
        assertThat(parsed.getDscp()).isEqualTo(0x2A);
        assertThat(parsed.getEcn()).isEqualTo(0x1);
        assertThat(parsed.getFragmentOffset()).isEqualTo(0x0123);
        assertThat(parsed.getTail()).isEqualTo(0x1FF);
    }

    @Data
    @ProtocolPacket(port = 7002)
    public static class Outer {
        @ProtocolField(order = 1, size = 8)  private int mark;
        @ProtocolField(order = 2, type = FieldType.NESTED) private BitFields inner;
        @ProtocolField(order = 3, size = 8)  private int end;
    }

    @Test
    void roundTripsNestedEntity() {
        // 先注册内部 codec(NESTED 解析依赖被引用类的 codec)
        new ProtocolCodec<>(BitFields.class);
        ProtocolCodec<Outer> codec = new ProtocolCodec<>(Outer.class);

        Outer original = new Outer();
        original.setMark(0xAB);
        BitFields inner = new BitFields();
        inner.setVersion(0x4);
        inner.setIhl(0x5);
        inner.setDscp(0x2A);
        inner.setEcn(0x1);
        inner.setFragmentOffset(0x0123);
        inner.setTail(0x1FF);
        original.setInner(inner);
        original.setEnd(0xCD);

        byte[] out = codec.serialize(original);
        Outer parsed = codec.deserialize(out);

        assertThat(parsed.getMark()).isEqualTo(0xAB);
        assertThat(parsed.getEnd()).isEqualTo(0xCD);
        assertThat(parsed.getInner().getVersion()).isEqualTo(0x4);
        assertThat(parsed.getInner().getFragmentOffset()).isEqualTo(0x0123);
        assertThat(parsed.getInner().getTail()).isEqualTo(0x1FF);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `./mvnw -q test -Dtest=CodecBitFieldTest`
Expected: 失败(当前 Codec 按 8 的倍数校验,4/6/2/13 不通过)

- [ ] **Step 3: 重构 ProtocolCodec(位字段 + NESTED,先不含动态长度/条件)**

`src/main/java/com/example/demo/protocol/core/ProtocolCodec.java` 完整替换为:
```java
package com.example.demo.protocol.core;

import com.example.demo.protocol.annotation.Payload;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.Packet;

import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.util.*;

public final class ProtocolCodec<T> {

    private final Class<T> clazz;
    private final List<FieldInfo> fixedFields; // 按 order 排序
    private final FieldInfo payloadField;      // @Payload 字段(向后兼容)

    public ProtocolCodec(Class<T> clazz) {
        this.clazz = clazz;
        List<FieldInfo> fixed = new ArrayList<>();
        FieldInfo payload = null;

        for (Field f : clazz.getDeclaredFields()) {
            if (f.isAnnotationPresent(Payload.class)) {
                payload = new FieldInfo(f);
            } else if (f.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolField.class)) {
                fixed.add(new FieldInfo(f));
            }
        }
        fixed.sort(Comparator.comparingInt(f -> f.order));
        this.fixedFields = fixed;
        this.payloadField = payload;
    }

    public T deserialize(byte[] rawData) {
        return deserialize(rawData, 0, rawData.length);
    }

    @SuppressWarnings("unchecked")
    public T deserialize(byte[] rawData, int offset, int length) {
        try {
            T obj = clazz.getDeclaredConstructor().newInstance();
            FieldContext.Impl ctx = (FieldContext.Impl) FieldContext.create(obj);
            BitCursor cursor = new BitCursor(rawData, offset);

            for (FieldInfo fi : fixedFields) {
                long size = resolveSize(fi, obj, ctx, true);
                Object value = readValue(fi, cursor, (int) size, ctx);
                fi.field.setAccessible(true);
                fi.field.set(obj, value);
                ctx.put(fi.name, value);
            }

            // 向后兼容:@Payload 取剩余字节
            if (payloadField != null) {
                int consumedBits = cursor.bitOffset();
                int consumedBytes = (consumedBits + 7) / 8;
                if (length > consumedBytes) {
                    payloadField.field.setAccessible(true);
                    payloadField.field.set(obj, Arrays.copyOfRange(rawData, offset + consumedBytes, offset + length));
                }
            }
            return obj;
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize " + clazz.getName(), e);
        }
    }

    public byte[] serialize(T obj) {
        try {
            FieldContext.Impl ctx = (FieldContext.Impl) FieldContext.create(obj);
            // 先把所有字段值装入 ctx(序列化时 ctx 一次性完整)
            for (FieldInfo fi : fixedFields) {
                fi.field.setAccessible(true);
                ctx.put(fi.name, fi.field.get(obj));
            }

            // 第一遍:算总位数
            int totalBits = 0;
            for (FieldInfo fi : fixedFields) {
                long size = resolveSize(fi, obj, ctx, false);
                if (size < 0) {
                    throw new IllegalStateException("cannot resolve size of field " + fi.name);
                }
                totalBits += size;
            }
            // @Payload 字节数
            byte[] payloadData = null;
            if (payloadField != null) {
                payloadField.field.setAccessible(true);
                payloadData = (byte[]) payloadField.field.get(obj);
                if (payloadData != null) {
                    totalBits += payloadData.length * 8;
                }
            }

            BitCursor cursor = new BitCursor((totalBits + 7) / 8);
            for (FieldInfo fi : fixedFields) {
                long size = resolveSize(fi, obj, ctx, false);
                writeValue(fi, obj, cursor, (int) size, ctx);
            }
            if (payloadField != null && payloadData != null) {
                cursor.writeBytes(payloadData);
            }
            return cursor.bytes();
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize " + clazz.getName(), e);
        }
    }

    // ---- 动态尺寸解析(Task 6/7 扩充 lengthField/presentIf) ----
    private long resolveSize(FieldInfo fi, Object obj, FieldContext ctx, boolean deserialize) throws Exception {
        // 1. 钩子优先
        if (obj instanceof DynamicSize ds) {
            long s = ds.computeSize(fi.name, ctx);
            if (s >= 0) {
                return s;
            }
        }
        // 2. 声明式 lengthField(Task 6 启用)
        if (!fi.lengthField.isEmpty() && ctx.hasRead(fi.lengthField)) {
            int ref = ctx.getInt(fi.lengthField);
            return fi.lengthUnit == LengthUnit.BYTES ? ref * 8L : ref;
        }
        // 3. 固定 size
        if (fi.size > 0) {
            return fi.size;
        }
        throw new IllegalStateException("cannot resolve size of field " + fi.name);
    }

    private Object readValue(FieldInfo fi, BitCursor cursor, int size, FieldContext ctx) throws Exception {
        FieldType type = effectiveType(fi);
        return switch (type) {
            case INT, UNSIGNED -> convertToFieldType(fi.field.getType(), cursor.readBits(size), type == FieldType.UNSIGNED);
            case BYTES -> cursor.readBytes(size);
            case STRING -> new String(cursor.readBytes(size), Charset.forName(fi.charset));
            case NESTED -> {
                ProtocolCodec<?> nested = codecFor(fi.field.getType());
                byte[] seg = cursor.readBytes(size);
                yield nested.deserialize(seg, 0, seg.length);
            }
        };
    }

    private void writeValue(FieldInfo fi, Object obj, BitCursor cursor, int size, FieldContext ctx) throws Exception {
        FieldType type = effectiveType(fi);
        fi.field.setAccessible(true);
        Object value = fi.field.get(obj);
        switch (type) {
            case INT, UNSIGNED -> {
                long v = convertFromFieldType(value);
                cursor.writeBits(v, size);
            }
            case BYTES -> cursor.writeBytes((byte[]) value);
            case STRING -> cursor.writeBytes(((String) value).getBytes(Charset.forName(fi.charset)));
            case NESTED -> {
                ProtocolCodec<?> nested = codecFor(fi.field.getType());
                cursor.writeBytes(nested.serialize(value));
            }
        }
    }

    private FieldType effectiveType(FieldInfo fi) {
        if (fi.type != FieldType.INT) {
            return fi.type; // 显式指定
        }
        // INT 默认:按 Java 类型推断(BYTES/STRING/NESTED)
        Class<?> t = fi.field.getType();
        if (t == byte[].class) {
            return FieldType.BYTES;
        }
        if (t == String.class) {
            return FieldType.STRING;
        }
        // 字段类型本身是 @ProtocolPacket 实体 → 当作 NESTED(也可显式 type=NESTED)
        if (!t.isPrimitive() && !Number.class.isAssignableFrom(t)
                && t.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolPacket.class)) {
            return FieldType.NESTED;
        }
        return FieldType.INT;
    }

    @SuppressWarnings("rawtypes")
    private static final Map<Class<?>, ProtocolCodec> NESTED_CACHE = new HashMap<>();

    @SuppressWarnings("unchecked")
    private ProtocolCodec<?> codecFor(Class<?> type) {
        ProtocolCodec<?> cached = getCodecCache(type);
        if (cached != null) {
            return cached;
        }
        ProtocolCodec<?> c = new ProtocolCodec<>(type);
        NESTED_CACHE.put(type, c);
        return c;
    }

    private static ProtocolCodec<?> getCodecCache(Class<?> type) {
        return NESTED_CACHE.get(type);
    }

    private static Object convertToFieldType(Class<?> type, long val, boolean unsigned) {
        if (unsigned) {
            if (type == int.class || type == Integer.class) return (int) val;
            if (type == long.class || type == Long.class) return val;
        }
        if (type == byte.class || type == Byte.class) return (byte) val;
        if (type == short.class || type == Short.class) return (short) val;
        if (type == int.class || type == Integer.class) return (int) val;
        if (type == long.class || type == Long.class) return val;
        return val;
    }

    private static long convertFromFieldType(Object value) {
        if (value == null) {
            return 0;
        }
        if (value instanceof Number n) {
            return n.longValue();
        }
        return 0;
    }

    // ---- pcap4j 适配(保留旧接口) ----
    public Packet toPacket(byte[] rawData, int offset, int length) {
        org.pcap4j.util.ByteArrays.validateBounds(rawData, offset, length);
        T obj = deserialize(rawData, offset, length);
        return new AutoPacket(rawData, offset, length, obj);
    }

    public Packet toPacket(T obj) {
        byte[] rawData = serialize(obj);
        return new AutoPacket(rawData, 0, rawData.length, obj);
    }

    public T fromPacket(Packet packet) {
        return deserialize(packet.getRawData());
    }

    // ---- 内部结构 ----
    private static final class FieldInfo {
        final Field field;
        final String name;
        final int order;
        final int size;
        final FieldType type;
        final String lengthField;
        final LengthUnit lengthUnit;
        final String presentIf;
        final String charset;

        FieldInfo(Field f) {
            this.field = f;
            this.name = f.getName();
            com.example.demo.protocol.annotation.ProtocolField ann = f.getAnnotation(com.example.demo.protocol.annotation.ProtocolField.class);
            this.order = ann.order();
            this.size = ann.size();
            this.type = ann.type();
            this.lengthField = ann.lengthField();
            this.lengthUnit = ann.lengthUnit();
            this.presentIf = ann.presentIf();
            this.charset = ann.charset();
        }
    }

    private final class AutoPacket extends AbstractPacket {
        private static final long serialVersionUID = 1L;
        private final byte[] rawData;
        private final AutoHeader autoHeader;

        AutoPacket(byte[] rawData, int offset, int length, T obj) {
            this.rawData = Arrays.copyOfRange(rawData, offset, offset + length);
            this.autoHeader = new AutoHeader(this.rawData, obj);
        }

        @Override public AutoHeader getHeader() { return autoHeader; }
        @Override public Packet getPayload() { return null; }
        @Override public AutoBuilder getBuilder() { return new AutoBuilder(); }
        @Override public int length() { return rawData.length; }
        @Override public String toString() { return "[AutoPacket " + clazz.getSimpleName() + "]"; }
        @Override public byte[] getRawData() { return rawData.clone(); }
    }

    private final class AutoHeader extends AbstractPacket.AbstractHeader {
        private static final long serialVersionUID = 1L;
        private final byte[] rawData;
        private final T obj;

        AutoHeader(byte[] rawData, T obj) {
            this.rawData = rawData;
            this.obj = obj;
        }

        @Override public int length() { return rawData.length; }
        @Override public byte[] getRawData() { return rawData.clone(); }
        @Override public String toString() { return obj != null ? obj.toString() : Arrays.toString(rawData); }
    }

    public final class AutoBuilder extends AbstractPacket.AbstractBuilder {
        private T obj;

        AutoBuilder() {
            try {
                this.obj = clazz.getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public AutoBuilder withObject(T obj) {
            this.obj = obj;
            return this;
        }

        @Override public AutoPacket build() {
            byte[] data = serialize(obj);
            return new AutoPacket(data, 0, data.length, obj);
        }
    }
}
```

> 说明:本任务先实现位字段 + NESTED + 固定 size + @Payload 兼容。`resolveSize` 里的 lengthField 分支已就位但 Task 6 才有测试;`presentIf` 在 Task 7 接入循环。

- [ ] **Step 4: 运行测试确认通过**

Run: `./mvnw -q test -Dtest=CodecBitFieldTest`
Expected: PASS(2 个测试)

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/CodecBitFieldTest.java
git commit -m "feat(codec): rewrite ProtocolCodec with bit cursor, types and NESTED"
```

---

## Task 6: 声明式长度引用(lengthField)

**Files:**
- Test: `src/test/java/com/example/demo/protocol/CodecLengthRefTest.java`
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`(完善序列化首遍)

- [ ] **Step 1: 写失败测试**

`src/test/java/com/example/demo/protocol/CodecLengthRefTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.LengthUnit;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CodecLengthRefTest {

    @Data
    @ProtocolPacket(port = 7003)
    public static class LengthRefPacket {
        @ProtocolField(order = 1, size = 8)  private int length;     // 后续 payload 字节数
        @ProtocolField(order = 2, type = FieldType.BYTES, lengthField = "length")
        private byte[] payload;
    }

    @Test
    void roundTripByteLengthRef() {
        ProtocolCodec<LengthRefPacket> codec = new ProtocolCodec<>(LengthRefPacket.class);
        LengthRefPacket original = new LengthRefPacket();
        original.setLength(3);
        original.setPayload(new byte[]{0x10, 0x20, 0x30});

        byte[] out = codec.serialize(original);
        // 结构:1字节length + 3字节payload = 4字节
        assertThat(out).containsExactly(0x03, 0x10, 0x20, 0x30);

        LengthRefPacket parsed = codec.deserialize(out);
        assertThat(parsed.getLength()).isEqualTo(3);
        assertThat(parsed.getPayload()).containsExactly(0x10, 0x20, 0x30);
    }

    @Data
    @ProtocolPacket(port = 7004)
    public static class BitLengthRefPacket {
        @ProtocolField(order = 1, size = 8)  private int len;        // 后续 bits 数
        @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "len", lengthUnit = LengthUnit.BITS)
        private String text;
    }

    @Test
    void roundTripBitLengthRefString() {
        ProtocolCodec<BitLengthRefPacket> codec = new ProtocolCodec<>(BitLengthRefPacket.class);
        BitLengthRefPacket original = new BitLengthRefPacket();
        String s = "Hi"; // 2 ASCII 字符 = 16 bits
        original.setLen(s.getBytes().length * 8); // 16
        original.setText(s);

        byte[] out = codec.serialize(original);
        // 1字节len + 2字节"Hi"
        assertThat(out).containsExactly(0x10, (byte) 'H', (byte) 'i');

        BitLengthRefPacket parsed = codec.deserialize(out);
        assertThat(parsed.getText()).isEqualTo("Hi");
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `./mvnw -q test -Dtest=CodecLengthRefTest`
Expected: 失败(序列化首遍算 totalBits 时 ctx 已装好字段值,lengthField 解析需确认 deserialize 端 ctx.hasRead 在 payload 前为 true)

- [ ] **Step 3: 检查/微调 ProtocolCodec**

Task 5 的 `resolveSize` 已含 lengthField 分支。需要确认:`deserialize` 时 `ctx.hasRead("length")` 在解析 payload 前为 true(因为 length 在 order=1 先解析,且解析后 ctx.put 了)。序列化端 ctx 一次性装满,`hasRead` 永远 true。

若测试已通过,跳到 Step 4。若失败,检查 `readValue` 中 BYTES/STRING 用 `cursor.readBytes(size)` 是否要求 size 是 8 的倍数——BITS 单位下 size 是 16,是 8 倍数,OK。无需改动,直接重跑。

- [ ] **Step 4: 运行测试确认通过**

Run: `./mvnw -q test -Dtest=CodecLengthRefTest`
Expected: PASS(2 个测试)

- [ ] **Step 5: 提交**

```bash
git add src/test/java/com/example/demo/protocol/CodecLengthRefTest.java
git commit -m "feat(codec): support declarative lengthField with BYTES/BITS units"
```

---

## Task 7: 条件字段(presentIf) + 反序列化循环接入

**Files:**
- Test: `src/test/java/com/example/demo/protocol/CodecConditionalTest.java`
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`

- [ ] **Step 1: 写失败测试**

`src/test/java/com/example/demo/protocol/CodecConditionalTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CodecConditionalTest {

    @Data
    @ProtocolPacket(port = 7005)
    public static class CondPacket {
        @ProtocolField(order = 1, size = 8) private int flag;
        @ProtocolField(order = 2, size = 8) private int always;
        @ProtocolField(order = 3, size = 8, presentIf = "flag==1") private int extra;
    }

    @Test
    void fieldPresentWhenConditionMet() {
        ProtocolCodec<CondPacket> codec = new ProtocolCodec<>(CondPacket.class);
        CondPacket original = new CondPacket();
        original.setFlag(1);
        original.setAlways(0xAA);
        original.setExtra(0xBB);

        byte[] out = codec.serialize(original);
        // flag=1 -> extra 出现 -> 3 字节
        assertThat(out).containsExactly(0x01, 0xAA, 0xBB);

        CondPacket parsed = codec.deserialize(out);
        assertThat(parsed.getFlag()).isEqualTo(1);
        assertThat(parsed.getAlways()).isEqualTo(0xAA);
        assertThat(parsed.getExtra()).isEqualTo(0xBB);
    }

    @Test
    void fieldAbsentWhenConditionNotMet() {
        ProtocolCodec<CondPacket> codec = new ProtocolCodec<>(CondPacket.class);
        CondPacket original = new CondPacket();
        original.setFlag(0);
        original.setAlways(0xAA);
        original.setExtra(0); // 不出现,值无所谓

        byte[] out = codec.serialize(original);
        // flag=0 -> extra 不出现 -> 2 字节
        assertThat(out).containsExactly(0x00, 0xAA);

        CondPacket parsed = codec.deserialize(out);
        assertThat(parsed.getFlag()).isEqualTo(0);
        assertThat(parsed.getAlways()).isEqualTo(0xAA);
        // extra 字段反序列化后保持 Java 默认值 0
        assertThat(parsed.getExtra()).isEqualTo(0);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `./mvnw -q test -Dtest=CodecConditionalTest`
Expected: 失败(条件未接入,序列化会写出 extra=0 → 0x00,0xAA,0x00;反序列化按 3 字节读)

- [ ] **Step 3: 接入 presentIf 到 serialize/deserialize 循环**

修改 `ProtocolCodec.java`。新增 `presentIf` 求值方法,并在两个循环开头跳过:

在类中新增方法:
```java
/** 求值 presentIf 表达式 "field==value",支持 short/int/long/十六进制 0x.. 字面量。 */
private static boolean evalPresentIf(String expr, FieldContext ctx) {
    if (expr == null || expr.isBlank()) {
        return true;
    }
    int eq = expr.indexOf("==");
    if (eq < 0) {
        throw new IllegalArgumentException("presentIf must be 'field==value': " + expr);
    }
    String left = expr.substring(0, eq).trim();
    String right = expr.substring(eq + 2).trim();
    long expected = right.toLowerCase().startsWith("0x")
            ? Long.parseLong(right.substring(2), 16)
            : Long.parseLong(right);
    return ctx.getInt(left) == expected;
}
```

在 `deserialize` 循环里,`for (FieldInfo fi : fixedFields)` 的第一行改为:
```java
for (FieldInfo fi : fixedFields) {
    if (!evalPresentIf(fi.presentIf, ctx)) {
        continue; // 条件不满足,跳过(不读字节,不入 ctx)
    }
    long size = resolveSize(fi, obj, ctx, true);
    ...
}
```

在 `serialize` 循环里(两处:算 totalBits 和写值)同样在最前面加:
```java
if (!evalPresentIf(fi.presentIf, ctx)) {
    continue;
}
```

注意:`serialize` 端 ctx 一次性装满,`ctx.getInt("flag")` 可取到(条件字段值本身不影响判断)。

- [ ] **Step 4: 运行测试确认通过**

Run: `./mvnw -q test -Dtest=CodecConditionalTest`
Expected: PASS(2 个测试)

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/CodecConditionalTest.java
git commit -m "feat(codec): support conditional fields via presentIf"
```

---

## Task 8: 注册期不变式校验(前向引用 / 字段存在)

**Files:**
- Test: `src/test/java/com/example/demo/protocol/CodecRegistryValidationTest.java`
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`(构造器加校验)

- [ ] **Step 1: 写失败测试**

`src/test/java/com/example/demo/protocol/CodecRegistryValidationTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CodecRegistryValidationTest {

    @Data
    @ProtocolPacket(port = 7006)
    public static class ForwardRef {
        @ProtocolField(order = 2, type = com.example.demo.protocol.core.FieldType.BYTES, lengthField = "len")
        private byte[] payload;
        @ProtocolField(order = 1, size = 8)
        private int len; // order 比 payload 小,合法
    }

    @Data
    @ProtocolPacket(port = 7007)
    public static class BackwardRef {
        @ProtocolField(order = 1, size = 8)
        private int len;
        @ProtocolField(order = 2, type = com.example.demo.protocol.core.FieldType.BYTES, lengthField = "len")
        private byte[] payload; // payload order=2 > len order=1 合法
    }

    @Data
    @ProtocolPacket(port = 7008)
    public static class NonExistentRef {
        @ProtocolField(order = 1, size = 8)
        private int len;
        @ProtocolField(order = 2, type = com.example.demo.protocol.core.FieldType.BYTES, lengthField = "ghost")
        private byte[] payload; // 引用不存在的字段
    }

    @Test
    void rejectsNonExistentLengthField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(NonExistentRef.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ghost");
    }

    @Test
    void acceptsValidLengthRef() {
        // BackwardRef: payload(order2) 引用 len(order1) — 合法
        new ProtocolCodec<>(BackwardRef.class);
        // ForwardRef: payload(order2) 引用 len(order1) — 合法(注:此例 order 已是 2 引 1)
        new ProtocolCodec<>(ForwardRef.class);
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `./mvnw -q test -Dtest=CodecRegistryValidationTest`
Expected: 失败(构造器未校验,NonExistentRef 不抛错)

- [ ] **Step 3: 构造器加校验**

在 `ProtocolCodec` 构造器末尾(设置 `this.fixedFields = fixed;` 之前)加入校验。在构造器内 `fixed.sort(...)` 之后插入:
```java
validateReferences(fixed);
```

并在类中新增静态方法:
```java
/** 注册期校验:lengthField 引用的字段必须存在,且 order 必须更小(禁止前向引用)。 */
private static void validateReferences(List<FieldInfo> sortedFields) {
    Map<String, Integer> nameToOrder = new HashMap<>();
    for (FieldInfo fi : sortedFields) {
        nameToOrder.put(fi.name, fi.order);
    }
    for (FieldInfo fi : sortedFields) {
        // lengthField 校验
        if (!fi.lengthField.isEmpty()) {
            Integer refOrder = nameToOrder.get(fi.lengthField);
            if (refOrder == null) {
                throw new IllegalArgumentException(
                        "field '" + fi.name + "' lengthField references unknown field '" + fi.lengthField + "'");
            }
            if (refOrder >= fi.order) {
                throw new IllegalArgumentException(
                        "field '" + fi.name + "' lengthField references '" + fi.lengthField
                                + "' which is not earlier in order (forward ref forbidden)");
            }
        }
        // presentIf 校验(只查字段存在)
        if (!fi.presentIf.isBlank()) {
            String left = fi.presentIf.substring(0, fi.presentIf.indexOf("==")).trim();
            if (!nameToOrder.containsKey(left)) {
                throw new IllegalArgumentException(
                        "field '" + fi.name + "' presentIf references unknown field '" + left + "'");
            }
        }
    }
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `./mvnw -q test -Dtest=CodecRegistryValidationTest`
Expected: PASS(2 个测试)

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/CodecRegistryValidationTest.java
git commit -m "feat(codec): validate lengthField/presentIf references at registration"
```

---

## Task 9: MyProtocol 零改动回归测试

**Files:**
- Test: `src/test/java/com/example/demo/protocol/MyProtocolRegressionTest.java`

- [ ] **Step 1: 写回归测试**

`src/test/java/com/example/demo/protocol/MyProtocolRegressionTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MyProtocolRegressionTest {

    @Test
    void myProtocolRoundTripsUnchanged() {
        ProtocolCodec<MyProtocol> codec = new ProtocolCodec<>(MyProtocol.class);

        MyProtocol original = new MyProtocol();
        original.setVersion((byte) 1);
        original.setType((byte) 2);
        original.setReserved((short) 0);
        original.setSequenceId(12345);
        original.setPayloadData(new byte[]{0x01, 0x02, 0x03, 0x04});

        byte[] out = codec.serialize(original);
        // 结构:1+1+2+4 头 + 4 payload = 12 字节
        assertThat(out).hasSize(12);

        MyProtocol parsed = codec.deserialize(out);
        assertThat(parsed.getVersion()).isEqualTo((byte) 1);
        assertThat(parsed.getType()).isEqualTo((byte) 2);
        assertThat(parsed.getReserved()).isEqualTo((short) 0);
        assertThat(parsed.getSequenceId()).isEqualTo(12345);
        assertThat(parsed.getPayloadData()).containsExactly(0x01, 0x02, 0x03, 0x04);
    }
}
```

- [ ] **Step 2: 运行测试确认通过**

Run: `./mvnw -q test -Dtest=MyProtocolRegressionTest`
Expected: PASS(@Payload 仍工作,size=8/16/32 仍按 bit)

- [ ] **Step 3: 提交**

```bash
git add src/test/java/com/example/demo/protocol/MyProtocolRegressionTest.java
git commit -m "test(codec): regression test for MyProtocol (backward compat)"
```

---

## Task 10: IPv4 头实体(验收标本)

**Files:**
- Create: `src/main/java/com/example/demo/protocol/Ipv4Header.java`
- Create: `src/main/java/com/example/demo/protocol/EthernetFrame.java`

- [ ] **Step 1: 实现 Ipv4Header(含 options 钩子)**

`src/main/java/com/example/demo/protocol/Ipv4Header.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldContext;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.DynamicSize;
import lombok.Data;
import lombok.ToString;

/**
 * IPv4 头(20 字节固定 + 可变 options)。options 长度由 (IHL-5)*4 字节决定,用钩子算。
 * Phase 1:headerChecksum 当普通字段(Phase 3 接校验和钩子)。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class Ipv4Header implements DynamicSize {

    @ProtocolField(order = 1, size = 4)  private int version;
    @ProtocolField(order = 2, size = 4)  private int ihl;          // 32-bit words
    @ProtocolField(order = 3, size = 8)  private int tos;          // 1.8.2 无 DSCP/ECN,整体 8 bit
    @ProtocolField(order = 4, size = 16) private int totalLength;
    @ProtocolField(order = 5, size = 16) private int identification;
    @ProtocolField(order = 6, size = 3)  private int flags;        // 3 bit(reserved/df/mf)
    @ProtocolField(order = 7, size = 13) private int fragmentOffset;
    @ProtocolField(order = 8, size = 8)  private int ttl;
    @ProtocolField(order = 9, size = 8)  private int protocol;
    @ProtocolField(order = 10, size = 16) private int headerChecksum;
    @ProtocolField(order = 11, size = 32) private int sourceIp;
    @ProtocolField(order = 12, size = 32) private int destinationIp;
    @ProtocolField(order = 13, type = FieldType.BYTES) private byte[] options;

    public Ipv4Header() {
        this.options = new byte[0];
    }

    @Override
    public long computeSize(String field, FieldContext ctx) {
        if ("options".equals(field)) {
            long headerBytes = ctx.getInt("ihl") * 4L; // IHL 单位是 32-bit word
            long optionBytes = headerBytes - 20;       // 固定部分 20 字节
            return Math.max(0, optionBytes) * 8;       // bit
        }
        return -1; // 其余字段走声明式 size
    }
}
```

- [ ] **Step 2: 实现 EthernetFrame(嵌套验收)**

`src/main/java/com/example/demo/protocol/EthernetFrame.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * 最简以太网帧:目的 MAC(6) + 源 MAC(6) + EtherType(2) + IP 头(嵌套)。
 * 仅用于验证 NESTED 嵌套 round-trip,非完整以太网(无 VLAN/帧尾)。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class EthernetFrame {

    @ProtocolField(order = 1, size = 48) private long dstMac;     // 6 字节当 long
    @ProtocolField(order = 2, size = 48) private long srcMac;
    @ProtocolField(order = 3, size = 16) private int etherType;
    @ProtocolField(order = 4, type = FieldType.NESTED) private Ipv4Header payload;
}
```

- [ ] **Step 3: 写 round-trip 测试**

`src/test/java/com/example/demo/protocol/Ipv4HeaderTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Ipv4HeaderTest {

    @Test
    void roundTripsMinimalHeader() {
        new ProtocolCodec<>(Ipv4Header.class);
        ProtocolCodec<Ipv4Header> codec = new ProtocolCodec<>(Ipv4Header.class);

        Ipv4Header original = new Ipv4Header();
        original.setVersion(4);
        original.setIhl(5); // 无 options -> 20 字节
        original.setTos(0);
        original.setTotalLength(20);
        original.setIdentification(0x1234);
        original.setFlags(0);
        original.setFragmentOffset(0);
        original.setTtl(64);
        original.setProtocol(17); // UDP
        original.setHeaderChecksum(0xABCD);
        original.setSourceIp(0x0A000001);      // 10.0.0.1
        original.setDestinationIp(0x0A000002); // 10.0.0.2
        original.setOptions(new byte[0]);

        byte[] out = codec.serialize(original);
        assertThat(out).hasSize(20);
        assertThat(out[0]).isEqualTo((byte) 0x45); // version=4, ihl=5

        Ipv4Header parsed = codec.deserialize(out);
        assertThat(parsed.getVersion()).isEqualTo(4);
        assertThat(parsed.getIhl()).isEqualTo(5);
        assertThat(parsed.getTotalLength()).isEqualTo(20);
        assertThat(parsed.getTtl()).isEqualTo(64);
        assertThat(parsed.getProtocol()).isEqualTo(17);
        assertThat(parsed.getHeaderChecksum()).isEqualTo(0xABCD);
        assertThat(parsed.getSourceIp()).isEqualTo(0x0A000001);
        assertThat(parsed.getDestinationIp()).isEqualTo(0x0A000002);
    }

    @Test
    void roundTripsWithOptions() {
        new ProtocolCodec<>(Ipv4Header.class);
        ProtocolCodec<Ipv4Header> codec = new ProtocolCodec<>(Ipv4Header.class);

        Ipv4Header original = new Ipv4Header();
        original.setVersion(4);
        original.setIhl(6); // 1 个 option word = 4 字节 options -> 24 字节头
        original.setTos(0);
        original.setTotalLength(24);
        original.setIdentification(0);
        original.setFlags(0);
        original.setFragmentOffset(0);
        original.setTtl(64);
        original.setProtocol(17);
        original.setHeaderChecksum(0);
        original.setSourceIp(0x0A000001);
        original.setDestinationIp(0x0A000002);
        original.setOptions(new byte[]{0x01, 0x01, 0x00, 0x00}); // 4 字节 NOP option

        byte[] out = codec.serialize(original);
        assertThat(out).hasSize(24); // 20 + 4 options

        Ipv4Header parsed = codec.deserialize(out);
        assertThat(parsed.getIhl()).isEqualTo(6);
        assertThat(parsed.getOptions()).containsExactly(0x01, 0x01, 0x00, 0x00);
    }

    @Test
    void roundTripsNestedEthernetFrame() {
        new ProtocolCodec<>(Ipv4Header.class);
        new ProtocolCodec<>(EthernetFrame.class);
        ProtocolCodec<EthernetFrame> codec = new ProtocolCodec<>(EthernetFrame.class);

        EthernetFrame frame = new EthernetFrame();
        frame.setDstMac(0xAABBCCDDEEFFL);
        frame.setSrcMac(0x112233445566L);
        frame.setEtherType(0x0800); // IPv4
        Ipv4Header ip = new Ipv4Header();
        ip.setVersion(4);
        ip.setIhl(5);
        ip.setTos(0);
        ip.setTotalLength(20);
        ip.setIdentification(0);
        ip.setFlags(0);
        ip.setFragmentOffset(0);
        ip.setTtl(64);
        ip.setProtocol(17);
        ip.setHeaderChecksum(0);
        ip.setSourceIp(0x0A000001);
        ip.setDestinationIp(0x0A000002);
        ip.setOptions(new byte[0]);
        frame.setPayload(ip);

        byte[] out = codec.serialize(frame);
        assertThat(out).hasSize(14 + 20); // 以太网头14 + IP头20

        EthernetFrame parsed = codec.deserialize(out);
        assertThat(parsed.getDstMac()).isEqualTo(0xAABBCCDDEEFFL);
        assertThat(parsed.getEtherType()).isEqualTo(0x0800);
        assertThat(parsed.getPayload().getIhl()).isEqualTo(5);
        assertThat(parsed.getPayload().getTtl()).isEqualTo(64);
    }
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `./mvnw -q test -Dtest=Ipv4HeaderTest`
Expected: PASS(3 个测试)

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/protocol/Ipv4Header.java src/main/java/com/example/demo/protocol/EthernetFrame.java src/test/java/com/example/demo/protocol/Ipv4HeaderTest.java
git commit -m "feat(protocol): add Ipv4Header and EthernetFrame entities with round-trip tests"
```

---

## Task 11: 真实 IPv4 包 pcap4j parity 验收

**Files:**
- Create: `src/test/java/com/example/demo/protocol/Ipv4ParityTest.java`

用 pcap4j **程序内构造**一个标准 IPv4 包,拿到它的真实 header 字节和字段值,再喂给我们的 codec,逐字段对比。这避免了「我自己序列化又自己解析」的自欺——裁判是 pcap4j。

> **pcap4j 1.8.2 API 要点(已核对源码):**
> - `IpVersion.IPV4`(非 IpV4Version),`IpNumber.UDP`(非 IpV4Number),`value()` 返回 `Byte`
> - ToS 是单一 `IpV4Tos` 对象(无 DSCP/ECN),用 `IpV4Rfc791Tos.newInstance((byte) tos)`
> - flags 是三个 boolean,无 `getFlags()`;getIhlAsInt 返回 32-bit word
> - `getSrcAddr()`/`getDstAddr()` 返回 `Inet4Address`,用 `InetAddress.getByName`

- [ ] **Step 1: 写 parity 测试**

`src/test/java/com/example/demo/protocol/Ipv4ParityTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class Ipv4ParityTest {

    @Test
    void ourCodecMatchesPcap4jFieldByField() throws Exception {
        // 1. 用 pcap4j 构造一个标准 IPv4 包(裁判)
        IpV4Packet pcapPkt = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0x1234)
                .reservedFlag(false)
                .dontFragmentFlag(true)
                .moreFragmentFlag(false)
                .fragmentOffset((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.1"))
                .dstAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.2"))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .build();

        byte[] headerBytes = pcapPkt.getHeader().getRawData(); // pcap4j 真实头字节

        // 2. 喂给我们的 codec
        new ProtocolCodec<>(Ipv4Header.class);
        ProtocolCodec<Ipv4Header> codec = new ProtocolCodec<>(Ipv4Header.class);
        Ipv4Header ours = codec.deserialize(headerBytes);

        // 3. 逐字段对比(parity)
        org.pcap4j.packet.IpV4Packet.IpV4Header pcapHeader = pcapPkt.getHeader();

        assertThat(ours.getVersion()).isEqualTo(pcapHeader.getVersion().value() & 0xFF);
        assertThat(ours.getIhl()).isEqualTo(pcapHeader.getIhlAsInt()); // 都是 32-bit word,值=5
        assertThat(ours.getTos()).isEqualTo(pcapHeader.getTos().value() & 0xFF);
        assertThat(ours.getTotalLength()).isEqualTo(pcapHeader.getTotalLengthAsInt());
        assertThat(ours.getIdentification()).isEqualTo(pcapHeader.getIdentificationAsInt());
        // flags: 我们的 3-bit = reserved<<2 | df<<1 | mf;pcap4j 是 3 个 boolean
        int expectedFlags = (pcapHeader.getReservedFlag() ? 4 : 0)
                | (pcapHeader.getDontFragmentFlag() ? 2 : 0)
                | (pcapHeader.getMoreFragmentFlag() ? 1 : 0);
        assertThat(ours.getFlags()).isEqualTo(expectedFlags);
        assertThat(ours.getFragmentOffset()).isEqualTo(pcapHeader.getFragmentOffset() & 0xFFFF);
        assertThat(ours.getTtl()).isEqualTo(pcapHeader.getTtlAsInt());
        assertThat(ours.getProtocol()).isEqualTo(pcapHeader.getProtocol().value() & 0xFF);
        assertThat(ours.getHeaderChecksum()).isEqualTo(pcapHeader.getHeaderChecksum() & 0xFFFF);

        // IP 地址对比:pcap4j 用 Inet4Address,我们用 int
        assertThat(ours.getSourceIp())
                .isEqualTo(ipToInt((java.net.Inet4Address) pcapHeader.getSrcAddr()));
        assertThat(ours.getDestinationIp())
                .isEqualTo(ipToInt((java.net.Inet4Address) pcapHeader.getDstAddr()));

        // 4. options 为空(ihl=5)
        assertThat(ours.getOptions()).isEmpty();
    }

    private static int ipToInt(java.net.Inet4Address addr) {
        byte[] b = addr.getAddress();
        return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
    }
}
```

- [ ] **Step 2: 运行测试确认通过**

Run: `./mvnw -q test -Dtest=Ipv4ParityTest`
Expected: PASS(若任一字段对不上,精确定位到对应特性 bug,修复后重跑)

> 调试提示:若 `getTtl()` 类型不匹配,注意 `getTtlAsInt()` 返回 int,与我们的 int 字段一致。

- [ ] **Step 3: 提交**

```bash
git add src/test/java/com/example/demo/protocol/Ipv4ParityTest.java
git commit -m "test(protocol): IPv4 field-by-field parity vs pcap4j"
```

---

## Task 12: Web UI 实时抓包解析分支

**Files:**
- Modify: `src/main/java/com/example/demo/service/PcapService.java`
- Modify: `src/main/resources/static/index.html`

在现有抓包流程加一条只读分支:抓到的包若是 IP 包,同时用我们的 `Ipv4Header` codec 解析,结果附在 capturedPackets 里。**不改原有 UDP 分发架构**。

- [ ] **Step 1: 在 PcapService 注册 Ipv4Header codec 并加 IP 解析分支**

修改 `PcapService.java` 的 `parsePacket` 方法,在方法开头(现有 `if (packet.contains(UdpPacket.class))` 之前)加 IP 分支,并在类字段区注册 codec:

在类字段区(如 `private final List<String> capturedPackets` 附近)加:
```java
private static final ProtocolCodec<com.example.demo.protocol.Ipv4Header> IPV4_CODEC;

static {
    IPV4_CODEC = new ProtocolCodec<>(com.example.demo.protocol.Ipv4Header.class);
}
```

修改 `parsePacket`,在方法体最前面插入:
```java
private String parsePacket(Packet packet) {
    // 新增:IPv4 解析分支(只读,不改 UDP 流程)
    if (packet.contains(org.pcap4j.packet.IpV4Packet.class)) {
        try {
            org.pcap4j.packet.IpV4Packet ip = packet.get(org.pcap4j.packet.IpV4Packet.class);
            byte[] headerBytes = ip.getHeader().getRawData();
            com.example.demo.protocol.Ipv4Header parsed = IPV4_CODEC.deserialize(headerBytes);
            return "[IPv4] v=" + parsed.getVersion()
                    + " ihl=" + parsed.getIhl()
                    + " ttl=" + parsed.getTtl()
                    + " proto=" + parsed.getProtocol()
                    + " src=" + formatIp(parsed.getSourceIp())
                    + " dst=" + formatIp(parsed.getDestinationIp();
        } catch (Exception e) {
            log.debug("IPv4 parse via our codec failed, fallback", e);
        }
    }

    // 原有 UDP 流程保持不变
    if (packet.contains(UdpPacket.class)) {
        // ... 原代码不动
    }
    return packet.toString();
}

private static String formatIp(int ip) {
    return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
}
```

需在文件顶部加 import(若 IDE 提示):
```java
import com.example.demo.protocol.core.ProtocolCodec;
```

- [ ] **Step 2: 在 index.html 展示解析结果(若已有抓包展示区则复用)**

先读 `src/main/resources/static/index.html` 确认现有展示结构,然后在抓包结果列表的渲染处让 `[IPv4]` 开头的条目原样显示(通常已有 `textContent` 直接渲染 capturedPackets)。若现有 UI 已直接展示 `packets` 数组的字符串,则无需改动。

Run: 读 `index.html`,只在「渲染未覆盖 IPv4 条目」时补一个 `<pre>` 或列表项。

- [ ] **Step 3: 全量测试确认无回归**

Run: `./mvnw -q test`
Expected: 全部 PASS(BitCursor/FieldContext/Codec 各测试/Ipv4Parity/MyProtocol 回归)

- [ ] **Step 4: 编译打包确认**

Run: `./mvnw -q package`
Expected: BUILD SUCCESS

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/service/PcapService.java src/main/resources/static/index.html
git commit -m "feat(ui): add IPv4 live-parse branch to capture (read-only, pcap4j parity)"
```

---

## Task 13: 全量验证 + 文档更新

- [ ] **Step 1: 全量测试**

Run: `./mvnw -q test`
Expected: 全部 PASS,无失败

- [ ] **Step 2: 全量编译打包**

Run: `./mvnw -q package`
Expected: BUILD SUCCESS

- [ ] **Step 3: 更新 README,记录 Phase 1 能力**

在 `README.md` 末尾追加:
```markdown
## Protocol Codec (Phase 1)

通用协议编解码引擎:用「实体类 + 注解」定义任意二进制协议。

### 支持的特性
- 位级字段(子字节,MSB 优先 / 网络序大端 / 跨字节边界)
- 声明式长度引用(lengthField,BYTES/BITS 单位)
- 条件字段(presentIf: "field==value")
- 协议嵌套(NESTED,实体引用实体)
- 字符串编码(charset)
- 算术复杂长度(DynamicSize 钩子)
- 类型:INT / UNSIGNED / BYTES / STRING / NESTED

### 验收
- 真实 IPv4 包与 pcap4j 逐字段 parity(`Ipv4ParityTest`)
- MyProtocol 零改动回归
- 位字段 / 嵌套 / 条件 / 长度引用 单元覆盖

### Phase 1 未覆盖(后续)
- TLV / 集合语义(COUNT / 重复不定个数字段)
- 复杂条件(位掩码 / &&)
- 校验和 / CRC 钩子
- 流重组 / 分片重组(过程性,留钩子)

### 示例
见 `com.example.demo.protocol.Ipv4Header` 和 `EthernetFrame`。
```

- [ ] **Step 4: 提交**

```bash
git add README.md
git commit -m "docs: document Phase 1 codec capabilities"
```

---

## 完成标志

全部 Task 完成后:
- [ ] `./mvnw -q test` 全绿
- [ ] `./mvnw -q package` 成功
- [ ] IPv4 parity 测试证明「实体类解析 == pcap4j 解析」
- [ ] MyProtocol 老代码零改动
- [ ] Web UI 抓真实包能看到 `[IPv4] ...` 解析结果
