# 通用协议编解码引擎 Phase 2b — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给引擎补齐「集合/变长字段怎么结束」的另外两种驱动:length 偏移(`lengthAdjust`)和字节级结束标记(`sentinel`)。

**Architecture:** `lengthAdjust` 是 `lengthField` 的常量偏移(解决 IP totalLen-20 这类);`sentinel` 是字节级结束标记,读到该字节停,复用 `type=LIST`/`BYTES`,与 countField/lengthField 互斥。sentinel 反序列化用 peek-then-read(给 BitCursor 加 `peekByte`),序列化追加标记字节。三种终止方式(countField/sentinel/lengthField)至多用一种,注册期校验。

**Tech Stack:** Java 25,Spring Boot 4.1,JUnit Jupiter 6 + AssertJ 3.27,Lombok。

**参考 spec:** `docs/superpowers/specs/2026-06-30-protocol-codec-phase2b-design.md`

**测试约定:** `./mvnw test -Dtest=XxxTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`(单类);全量 `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`。Git Bash on Windows。`tr` 去除非 ASCII 注释字符以免 grep 报错。

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `annotation/ProtocolField.java` | 加 `lengthAdjust`/`sentinel` 属性(带默认值) | 修改 |
| `core/BitCursor.java` | 加 `peekByte()`(sentinel 反序列化用) | 修改 |
| `core/ProtocolCodec.java` | sentinel 分支 + lengthAdjust 应用 + 注册校验 | 修改 |
| `protocol/IpFragment.java` | length 驱动试金石实体 | 新建 |
| `protocol/CStringPacket.java` | sentinel blob 试金石实体 | 新建 |
| `protocol/DnsNameSentinel.java` | sentinel-LIST 试金石(复用 DnsLabel) | 新建 |
| `test/.../LengthAdjustTest.java` | length 偏移 round-trip | 新建 |
| `test/.../SentinelBytesTest.java` | sentinel blob round-trip | 新建 |
| `test/.../SentinelListTest.java` | sentinel-LIST round-trip | 新建 |
| `test/.../SentinelValidationTest.java` | 互斥 + 范围校验 | 新建 |

包路径 `com.example.demo.protocol.*`。所有测试为纯 JUnit。

---

## Task 1: @ProtocolField 加 lengthAdjust / sentinel

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/annotation/ProtocolField.java`

- [ ] **Step 1: 加两个属性**

替换 `ProtocolField.java` 全文为:
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
}
```

- [ ] **Step 2: 编译确认(Phase 1/2a 实体不受影响,新属性有默认值)**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/annotation/ProtocolField.java
git commit -m "feat(codec): add lengthAdjust/sentinel to @ProtocolField"
```

---

## Task 2: BitCursor 加 peekByte

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/BitCursor.java`

- [ ] **Step 1: 写失败测试**

在 `src/test/java/com/example/demo/protocol/core/BitCursorTest.java` 末尾(最后一个 `}` 之前)加测试方法:
```java
    @Test
    void peekByteDoesNotAdvanceCursor() {
        byte[] data = {0x12, 0x34};
        BitCursor c = new BitCursor(data, 0);
        assertThat(c.peekByte()).isEqualTo(0x12);
        assertThat(c.bitOffset()).isEqualTo(0);  // 未推进
        c.readBits(8);
        assertThat(c.peekByte()).isEqualTo(0x34);
    }
```

- [ ] **Step 2: 运行确认失败**

Run: `./mvnw test -Dtest=BitCursorTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(peekByte 不存在)

- [ ] **Step 3: 实现 peekByte**

在 `BitCursor.java` 的 `remainingFromCursor()` 方法附近加:
```java
    /** 偷看当前字节(游标必须字节对齐),不推进游标。供 sentinel 判定用。 */
    public int peekByte() {
        if (bitPos % 8 != 0) {
            throw new IllegalStateException("peekByte requires byte-aligned cursor, bitPos=" + bitPos);
        }
        int byteIdx = baseByte + bitPos / 8;
        if (byteIdx >= data.length) {
            return -1;  // 无字节可读(已到末尾)
        }
        return data[byteIdx] & 0xFF;
    }
```

- [ ] **Step 4: 运行确认通过**

Run: `./mvnw test -Dtest=BitCursorTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 6, Failures: 0`(原 5 + 新 1)

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/BitCursor.java src/test/java/com/example/demo/protocol/core/BitCursorTest.java
git commit -m "feat(codec): add BitCursor.peekByte for sentinel detection"
```

---

## Task 3: FieldInfo 读新属性 + lengthAdjust 应用到 lengthField

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`

- [ ] **Step 1: FieldInfo 加两个字段**

在 `ProtocolCodec.java` 的 `FieldInfo` 内部类里,加 `final int lengthAdjust;` 和 `final int sentinel;`。
- 在 `FieldInfo(Field f)` 构造器里加:`this.lengthAdjust = ann.lengthAdjust();` 和 `this.sentinel = ann.sentinel();`
- 在私有 `FieldInfo(Field f, String name)`(@Payload 用)构造器里加:`this.lengthAdjust = 0;` 和 `this.sentinel = -1;`

- [ ] **Step 2: lengthAdjust 应用到 resolveSize 的 lengthField 分支**

找到 `resolveSize` 里第 2 步 lengthField 分支(当前是):
```java
        // 2. 声明式 lengthField(Task 6 启用)
        if (!fi.lengthField.isEmpty() && ctx.hasRead(fi.lengthField)) {
            int ref = ctx.getInt(fi.lengthField);
            return fi.lengthUnit == LengthUnit.BYTES ? ref * 8L : ref;
        }
```
改为(加 lengthAdjust):
```java
        // 2. 声明式 lengthField(Phase 2b 加 lengthAdjust 偏移)
        if (!fi.lengthField.isEmpty() && ctx.hasRead(fi.lengthField)) {
            int ref = ctx.getInt(fi.lengthField);
            if (fi.lengthUnit == LengthUnit.BYTES) {
                return (ref + fi.lengthAdjust) * 8L;
            }
            return ref;  // BITS 单位不应用字节偏移
        }
```

- [ ] **Step 3: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 4: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java
git commit -m "feat(codec): read lengthAdjust/sentinel in FieldInfo; apply lengthAdjust to lengthField"
```

---

## Task 4: length 驱动试金石(lengthAdjust)+ 测试

**Files:**
- Create: `src/main/java/com/example/demo/protocol/IpFragment.java`
- Test: `src/test/java/com/example/demo/protocol/LengthAdjustTest.java`

- [ ] **Step 1: 创建 IpFragment 实体**

```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * IP 分片(简化):totalLen 字段决定 payload 字节数。
 * payload 占 totalLen - 20 字节(20 是 IP 头固定开销),用 lengthAdjust=-20 表达。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class IpFragment {

    @ProtocolField(order = 1, size = 16)
    private int totalLen;

    @ProtocolField(order = 2, type = FieldType.BYTES,
            lengthField = "totalLen", lengthAdjust = -20)
    private byte[] payload;

    public IpFragment() {
        this.payload = new byte[0];
    }
}
```

- [ ] **Step 2: 写测试**

创建 `src/test/java/com/example/demo/protocol/LengthAdjustTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LengthAdjustTest {

    @Test
    void roundTripsWithLengthAdjust() {
        ProtocolCodec<IpFragment> codec = new ProtocolCodec<>(IpFragment.class);

        IpFragment f = new IpFragment();
        f.setTotalLen(24);   // payload 应占 24 - 20 = 4 字节
        f.setPayload(new byte[]{0x01, 0x02, 0x03, 0x04});

        byte[] out = codec.serialize(f);
        // 2字节 totalLen + 4字节 payload = 6字节
        assertThat(out).containsExactly(0x00, 0x18, 0x01, 0x02, 0x03, 0x04);  // 24 = 0x0018

        IpFragment parsed = codec.deserialize(out);
        assertThat(parsed.getTotalLen()).isEqualTo(24);
        assertThat(parsed.getPayload()).containsExactly(0x01, 0x02, 0x03, 0x04);
    }

    @Test
    void roundTripsEmptyPayloadWhenLengthMatchesHeader() {
        // totalLen = 20,adjust=-20 → payload = 0 字节(边界情况)
        ProtocolCodec<IpFragment> codec = new ProtocolCodec<>(IpFragment.class);

        IpFragment f = new IpFragment();
        f.setTotalLen(20);  // 20 - 20 = 0 字节 payload
        f.setPayload(new byte[0]);

        byte[] out = codec.serialize(f);
        assertThat(out).containsExactly(0x00, 0x14);  // 仅 totalLen(20=0x14),无 payload
    }
}
```

- [ ] **Step 3: 运行确认通过**

Run: `./mvnw test -Dtest=LengthAdjustTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 2, Failures: 0`

- [ ] **Step 4: 提交**

```bash
git add src/main/java/com/example/demo/protocol/IpFragment.java src/test/java/com/example/demo/protocol/LengthAdjustTest.java
git commit -m "feat(codec): lengthAdjust support with IpFragment specimen"
```

---

## Task 5: sentinel 反序列化/序列化分支(核心)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`

这是 Phase 2b 核心:sentinel 在 readValue(反序列化)、writeValue(序列化)、resolveSize(算总位数)三处加分支。

- [ ] **Step 1: 写失败测试(sentinel blob)**

创建 `src/test/java/com/example/demo/protocol/SentinelBytesTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SentinelBytesTest {

    @Data
    @ProtocolPacket(port = 0)
    public static class CStringPacket {
        @ProtocolField(order = 1, type = FieldType.BYTES, sentinel = 0x00)
        private byte[] text;

        public CStringPacket() {
            this.text = new byte[0];
        }
    }

    @Test
    void roundTripsSentinelBlob() {
        ProtocolCodec<CStringPacket> codec = new ProtocolCodec<>(CStringPacket.class);

        CStringPacket p = new CStringPacket();
        p.setText("Hi".getBytes());   // 48 69

        byte[] out = codec.serialize(p);
        // "Hi" + 0x00 结束标记
        assertThat(out).containsExactly(0x48, 0x69, 0x00);

        CStringPacket parsed = codec.deserialize(out);
        assertThat(parsed.getText()).containsExactly(0x48, 0x69);  // 不含 0x00
    }

    @Test
    void roundTripsEmptySentinelBlob() {
        ProtocolCodec<CStringPacket> codec = new ProtocolCodec<>(CStringPacket.class);

        CStringPacket p = new CStringPacket();
        p.setText(new byte[0]);  // 空,直接以标记开始

        byte[] out = codec.serialize(p);
        assertThat(out).containsExactly(0x00);  // 仅标记

        CStringPacket parsed = codec.deserialize(out);
        assertThat(parsed.getText()).isEmpty();
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `./mvnw test -Dtest=SentinelBytesTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(sentinel 未实现)

- [ ] **Step 3: resolveSize 加 sentinel 分支(序列化算总位数)**

在 `resolveSize` 方法最前面(LIST 分支之前)加 sentinel 分支:
```java
    private long resolveSize(FieldInfo fi, Object obj, FieldContext ctx, boolean deserialize, int remainingBits) throws Exception {
        // -1. sentinel:数据位数 + 8(标记字节)
        if (fi.sentinel >= 0) {
            return sentinelTotalBits(fi, obj);
        }
        // 0. LIST:总位数 = 各元素 serialize 后累加
        if (effectiveType(fi) == FieldType.LIST) {
            return listTotalBits(fi, obj);
        }
        ... // 后续不变
```

并新增私有方法 `sentinelTotalBits`(放在 `listTotalBits` 附近):
```java
    /**
     * 计算 sentinel 字段总位数(供 resolveSize 序列化用):数据位数 + 8(标记字节)。
     * - BYTES:数据 = 字段当前字节数
     * - LIST:数据 = 各元素 serialize 累加
     */
    private long sentinelTotalBits(FieldInfo fi, Object obj) throws Exception {
        fi.field.setAccessible(true);
        Object value = fi.field.get(obj);
        long dataBits;
        if (value instanceof byte[] bytes) {
            dataBits = bytes.length * 8L;
        } else if (value instanceof java.util.List<?> list) {
            ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
            long total = 0;
            for (Object elem : list) {
                total += serializeNested(elementCodec, elem).length * 8L;
            }
            dataBits = total;
        } else {
            throw new IllegalStateException("sentinel field " + fi.name + " must be byte[] or List");
        }
        return dataBits + 8;  // + 标记字节
    }
```

- [ ] **Step 4: readValue 加 sentinel 分支(反序列化)**

在 `readValue` 的 switch 里,**在最前面**加 sentinel 判断(在 type 分派之前,因为 sentinel 跨 BYTES/LIST)。把 `readValue` 改为(注意 sentinel 字段也可能同时 type=LIST,故先判 sentinel):
```java
    private Object readValue(FieldInfo fi, BitCursor cursor, int size, FieldContext ctx) throws Exception {
        // sentinel 反序列化(跨 BYTES/LIST,优先)
        if (fi.sentinel >= 0) {
            return readSentinelValue(fi, cursor);
        }
        FieldType type = effectiveType(fi);
        return switch (type) {
            ... // 原 switch 不变
        };
    }
```

并新增私有方法 `readSentinelValue`:
```java
    /**
     * sentinel 反序列化:读到标记字节停。
     * - BYTES:逐字节读到 == sentinel,消费标记,返回之前的字节
     * - LIST:peek → 命中 sentinel 则消费标记+停;否则读一个元素,循环
     */
    private Object readSentinelValue(FieldInfo fi, BitCursor cursor) throws Exception {
        if (effectiveType(fi) == FieldType.LIST) {
            ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
            java.util.List<Object> list = new java.util.ArrayList<>();
            while (true) {
                int peek = cursor.peekByte();
                if (peek == fi.sentinel) {
                    cursor.skipBits(8);  // 消费标记字节
                    break;
                }
                if (peek < 0) {
                    throw new IllegalStateException(
                            "sentinel field " + fi.name + ": reached end of data without marker " + fi.sentinel);
                }
                byte[] rest = cursor.remainingFromCursor();
                Object elem = elementCodec.deserialize(rest, 0, rest.length);
                list.add(elem);
                cursor.skipBits((int) (serializeNested(elementCodec, elem).length * 8L));
            }
            return list;
        } else {
            // BYTES:逐字节读
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            while (true) {
                int peek = cursor.peekByte();
                if (peek == fi.sentinel) {
                    cursor.skipBits(8);  // 消费标记
                    break;
                }
                if (peek < 0) {
                    throw new IllegalStateException(
                            "sentinel field " + fi.name + ": reached end of data without marker " + fi.sentinel);
                }
                bos.write(cursor.readBits(8));  // 读一字节(取低8位)
            }
            return bos.toByteArray();
        }
    }
```

- [ ] **Step 5: writeValue 加 sentinel 分支(序列化)**

在 `writeValue` 的 switch 之前加 sentinel 判断:
```java
    private void writeValue(FieldInfo fi, Object obj, BitCursor cursor, int size, FieldContext ctx) throws Exception {
        // sentinel 序列化:写数据 + 追加标记字节
        if (fi.sentinel >= 0) {
            writeSentinelValue(fi, obj, cursor);
            return;
        }
        FieldType type = effectiveType(fi);
        fi.field.setAccessible(true);
        Object value = fi.field.get(obj);
        switch (type) {
            ... // 原 switch 不变
        }
    }
```

并新增私有方法 `writeSentinelValue`:
```java
    /** sentinel 序列化:写数据 + 追加标记字节。 */
    private void writeSentinelValue(FieldInfo fi, Object obj, BitCursor cursor) throws Exception {
        fi.field.setAccessible(true);
        Object value = fi.field.get(obj);
        if (value instanceof byte[] bytes) {
            cursor.writeBytes(bytes);
        } else if (value instanceof java.util.List<?> list) {
            ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
            for (Object elem : list) {
                cursor.writeBytes(serializeNested(elementCodec, elem));
            }
        } else {
            throw new IllegalStateException("sentinel field " + fi.name + " must be byte[] or List");
        }
        cursor.writeBits(fi.sentinel, 8);  // 追加标记字节
    }
```

- [ ] **Step 6: 运行测试确认通过**

Run: `./mvnw test -Dtest=SentinelBytesTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 2, Failures: 0`

- [ ] **Step 7: 全量回归(确认 Phase 1+2a 未破)**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 29 + BitCursor peek + lengthAdjust 2 + sentinel 2 = 应 34 左右)

- [ ] **Step 8: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/SentinelBytesTest.java
git commit -m "feat(codec): sentinel termination (byte-level) for BYTES and LIST"
```

---

## Task 6: sentinel-LIST 试金石 + 测试

**Files:**
- Create: `src/main/java/com/example/demo/protocol/DnsNameSentinel.java`
- Test: `src/test/java/com/example/demo/protocol/SentinelListTest.java`

- [ ] **Step 1: 创建 DnsNameSentinel(复用 DnsLabel,sentinel 终止)**

```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * DNS Name(sentinel 驱动变体):一串 DnsLabel,以 0x00 结束。
 * 与 Phase 2a 的 DnsQuestion(count 驱动)对比:这里用 sentinel=0x00。
 * 注意:真实 DNS 的 0x00 是「长度0的label」语义(元素内判定,Phase 2c);
 *       Phase 2b 视 0x00 为独立结束字节,简化但能覆盖大部分场景。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DnsNameSentinel {

    @ProtocolField(order = 1, type = FieldType.LIST,
            elementClass = DnsLabel.class, sentinel = 0x00)
    private List<DnsLabel> labels = new ArrayList<>();
}
```

- [ ] **Step 2: 写测试**

创建 `src/test/java/com/example/demo/protocol/SentinelListTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SentinelListTest {

    @Test
    void roundTripsSentinelList() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsNameSentinel> codec = new ProtocolCodec<>(DnsNameSentinel.class);

        DnsNameSentinel name = new DnsNameSentinel();
        name.getLabels().add(new DnsLabel("www"));
        name.getLabels().add(new DnsLabel("com"));

        byte[] out = codec.serialize(name);
        // www(03 77 77 77) + com(03 63 6f 6d) + 0x00 结束
        assertThat(out).containsExactly(
                0x03, 0x77, 0x77, 0x77,
                0x03, 0x63, 0x6f, 0x6d,
                0x00);

        DnsNameSentinel parsed = codec.deserialize(out);
        assertThat(parsed.getLabels()).hasSize(2);
        assertThat(parsed.getLabels().get(0).getContent()).containsExactly('w', 'w', 'w');
        assertThat(parsed.getLabels().get(1).getContent()).containsExactly('c', 'o', 'm');
    }

    @Test
    void roundTripsEmptySentinelList() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsNameSentinel> codec = new ProtocolCodec<>(DnsNameSentinel.class);

        DnsNameSentinel name = new DnsNameSentinel();  // 空 labels

        byte[] out = codec.serialize(name);
        assertThat(out).containsExactly(0x00);  // 直接以标记开始

        DnsNameSentinel parsed = codec.deserialize(out);
        assertThat(parsed.getLabels()).isEmpty();
    }
}
```

- [ ] **Step 3: 运行确认通过**

Run: `./mvnw test -Dtest=SentinelListTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 2, Failures: 0`

- [ ] **Step 4: 提交**

```bash
git add src/main/java/com/example/demo/protocol/DnsNameSentinel.java src/test/java/com/example/demo/protocol/SentinelListTest.java
git commit -m "feat(codec): sentinel-LIST specimen with DnsNameSentinel"
```

---

## Task 7: 注册期校验(互斥 + 范围)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`
- Test: `src/test/java/com/example/demo/protocol/SentinelValidationTest.java`

- [ ] **Step 1: 写失败测试**

创建 `src/test/java/com/example/demo/protocol/SentinelValidationTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SentinelValidationTest {

    /** sentinel 与 countField 同时给 → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BothSentinelAndCount {
        @ProtocolField(order = 1, size = 8) private int n;
        @ProtocolField(order = 2, type = FieldType.LIST,
                countField = "n", elementClass = DnsLabel.class, sentinel = 0x00)
        private java.util.List<DnsLabel> items;
    }

    @Test
    void rejectsSentinelWithCountField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BothSentinelAndCount.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sentinel");
    }

    /** sentinel 与 lengthField 同时给 → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BothSentinelAndLength {
        @ProtocolField(order = 1, size = 8) private int len;
        @ProtocolField(order = 2, type = FieldType.BYTES,
                lengthField = "len", sentinel = 0x00)
        private byte[] data;
    }

    @Test
    void rejectsSentinelWithLengthField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BothSentinelAndLength.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sentinel");
    }

    /** sentinel 越界(>255)→ 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class SentinelOutOfRange {
        @ProtocolField(order = 1, type = FieldType.BYTES, sentinel = 300)
        private byte[] data;
    }

    @Test
    void rejectsSentinelOutOfRange() {
        assertThatThrownBy(() -> new ProtocolCodec<>(SentinelOutOfRange.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sentinel");
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `./mvnw test -Dtest=SentinelValidationTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(校验未实现)

- [ ] **Step 3: 扩展 validateReferences 加 sentinel 校验**

在 `ProtocolCodec.java` 的 `validateReferences` 方法里,`for (FieldInfo fi : sortedFields)` 循环内,在所有现有校验(lengthField/presentIf/LIST)之后,加 sentinel 校验块:
```java
            // sentinel 校验(Phase 2b)
            if (fi.sentinel >= 0) {
                if (fi.sentinel > 0xFF) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "' sentinel=" + fi.sentinel + " out of range (0x00-0xFF)");
                }
                if (!fi.countField.isEmpty()) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': sentinel and countField are mutually exclusive");
                }
                if (!fi.lengthField.isEmpty()) {
                    throw new IllegalArgumentException(
                            "field '" + fi.name + "': sentinel and lengthField are mutually exclusive");
                }
            }
```

- [ ] **Step 4: 运行确认通过**

Run: `./mvnw test -Dtest=SentinelValidationTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 3, Failures: 0`

- [ ] **Step 5: 全量回归**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(应约 39 个测试)

- [ ] **Step 6: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/SentinelValidationTest.java
git commit -m "feat(codec): validate sentinel range and mutual exclusion with count/length"
```

---

## Task 8: 全量验证 + 文档更新

- [ ] **Step 1: 全量测试**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿

- [ ] **Step 2: 全量编译打包**

Run: `./mvnw package 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 更新 README**

在 `README.md` 的「### Phase 2a」之后,加一节「### Phase 2b」:
```markdown
### Phase 2b(本版本新增)

- **length 偏移** —— `lengthAdjust`:字段字节长度 = `lengthField值 + lengthAdjust`(解决 IP totalLen-20 这类)
- **sentinel 结束标记** —— `sentinel=0xNN`:读到该字节就停。支持 BYTES(blob)和 LIST(重复实体),与 countField/lengthField 互斥

示例:
```java
// IP payload:占 totalLen - 20 字节
@ProtocolField(type=BYTES, lengthField="totalLen", lengthAdjust=-20) private byte[] payload;

// C 字符串:读到 0x00 结束
@ProtocolField(type=BYTES, sentinel=0x00) private byte[] text;
```

### 仍未覆盖(后续 Phase)

- 元素内字段级 sentinel(如 DNS 的「label 长度=0 表示结束」)
- 异质 TLV(type → 子结构分派,如 TCP/DHCP Options)
- 复杂条件(位掩码 / `&&`)
- 校验和 / CRC 钩子
- 流重组 / 分片重组
```
(把原「### 仍未覆盖」替换为上面的新内容)

- [ ] **Step 4: 提交**

```bash
git add README.md
git commit -m "docs: document Phase 2b lengthAdjust and sentinel capabilities"
```

---

## 完成标志

全部 Task 完成后:
- [ ] `./mvnw test` 全绿
- [ ] `./mvnw package` 成功
- [ ] length 偏移:IpFragment round-trip(totalLen=24→payload 4字节)
- [ ] sentinel blob:CStringPacket round-trip(`Hi`→`48 69 00`)
- [ ] sentinel-LIST:DnsNameSentinel round-trip(多 label + 0x00)
- [ ] 互斥/范围校验生效
- [ ] Phase 1+2a 全量回归不破
