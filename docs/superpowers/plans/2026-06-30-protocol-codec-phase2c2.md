# 通用协议编解码引擎 Phase 2c2 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 支持 LIST 的元素内 sentinel(DNS QName 的 length=0 表示结束),填补 Phase 2b 留的缺口。做完能 round-trip 真实 DNS QName 的 label 序列。

**Architecture:** 新增 `sentinelOn`(元素终止判定字段名)/`sentinelValue`(==此值则终止)两个注解属性。LIST 字段若声明 sentinelOn,反序列化时 peek 元素首字段值(从 elementClass 查该字段 size),==sentinelValue 则消费+停;否则正常读元素。序列化末尾追加 sentinelValue。与 countField/sentinel(2b)互斥,注册期校验。**无新 FieldType。**

**Tech Stack:** Java 25,Spring Boot 4.1,JUnit Jupiter 6 + AssertJ 3.27,Lombok。

**参考 spec:** `docs/superpowers/specs/2026-06-30-protocol-codec-phase2c2-design.md`

**测试约定:** `./mvnw test -Dtest=XxxTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`(单类);全量 `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`。Git Bash on Windows。

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `annotation/ProtocolField.java` | 加 `sentinelOn`/`sentinelValue` 属性 | 修改 |
| `core/ProtocolCodec.java` | FieldInfo 读新属性 + 注册期校验 + LIST sentinelOn 子分支 | 修改 |
| `protocol/DnsName.java` | 真实 DNS QName 实体(复用 DnsLabel) | 新建 |
| `test/.../DnsNameElementSentinelTest.java` | round-trip | 新建 |
| `test/.../DnsNameSentinelEdgeTest.java` | 空 QName / 读到末尾 | 新建 |
| `test/.../SentinelOnValidationTest.java` | 互斥 + 字段不存在校验 | 新建 |

包路径 `com.example.demo.protocol.*`。所有测试为纯 JUnit。

---

## Task 1: @ProtocolField 加 sentinelOn/sentinelValue

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/annotation/ProtocolField.java`

- [ ] **Step 1: 加两个属性**

在 `ProtocolField.java` 的 `sentinel()`(Phase 2b)之后,加两个属性:
```java
    /** sentinel 结束标记字节值(0x00–0xFF);-1 表示不用。读到该字节就结束。与 countField/lengthField 互斥。 */
    int sentinel() default -1;

    /** LIST 元素内 sentinel:元素里哪个字段判定终止(peek 该字段值)。与 countField/sentinel 互斥。 */
    String sentinelOn() default "";

    /** sentinelOn 字段==此值则终止 LIST。 */
    long sentinelValue() default 0;
```

- [ ] **Step 2: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`(新属性有默认值,老实体不受影响)

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/annotation/ProtocolField.java
git commit -m "feat(codec): add sentinelOn/sentinelValue to @ProtocolField"
```

---

## Task 2: ProtocolCodec LIST sentinelOn 子分支 + FieldInfo(核心)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`

这是 Phase 2c2 核心。FieldInfo 读新属性 + 注册期查 sentinelOn 字段 size;readValue/writeValue 的 LIST 分支加 sentinelOn 子分支。

- [ ] **Step 1: 写失败测试**

创建 `src/test/java/com/example/demo/protocol/DnsNameElementSentinelTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DnsNameElementSentinelTest {

    @Test
    void roundTripsRealDnsName() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsName> codec = new ProtocolCodec<>(DnsName.class);

        DnsName name = new DnsName();
        name.getLabels().add(new DnsLabel("www"));
        name.getLabels().add(new DnsLabel("example"));
        name.getLabels().add(new DnsLabel("com"));

        byte[] out = codec.serialize(name);
        // 真实 DNS QName:www + example + com + 0x00(结束)
        assertThat(out).containsExactly(
                0x03, 0x77, 0x77, 0x77,                           // "www"
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,   // "example"
                0x03, 0x63, 0x6f, 0x6d,                           // "com"
                0x00);                                            // 结束(length=0)

        DnsName parsed = codec.deserialize(out);
        assertThat(parsed.getLabels()).hasSize(3);
        assertThat(parsed.getLabels().get(0).getContent()).containsExactly('w', 'w', 'w');
        assertThat(parsed.getLabels().get(1).getContent()).containsExactly('e', 'x', 'a', 'm', 'p', 'l', 'e');
        assertThat(parsed.getLabels().get(2).getContent()).containsExactly('c', 'o', 'm');
    }
}
```

- [ ] **Step 2: 创建 DnsName 实体**

创建 `src/main/java/com/example/demo/protocol/DnsName.java`:
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
 * 真实 DNS QName:一串 DnsLabel,以 length=0 的 label(即 0x00 字节)结束。
 * 用 sentinelOn="length", sentinelValue=0 表达元素内 sentinel。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DnsName {

    @ProtocolField(order = 1, type = FieldType.LIST,
            elementClass = DnsLabel.class,
            sentinelOn = "length", sentinelValue = 0)
    private List<DnsLabel> labels = new ArrayList<>();
}
```

- [ ] **Step 3: 运行确认失败**

Run: `./mvnw test -Dtest=DnsNameElementSentinelTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(LIST sentinelOn 未实现,走 countField 路径,无 countField 报错或读不出)

- [ ] **Step 4: FieldInfo 加字段 + 注册期查 sentinelOn size**

在 `FieldInfo` 内部类加:`final String sentinelOn;`、`final long sentinelValue;`、`final int sentinelOnSize;`(缓存元素 sentinelOn 字段的 size)。

在 `FieldInfo(Field f)` 构造器加:
```java
            this.sentinelOn = ann.sentinelOn();
            this.sentinelValue = ann.sentinelValue();
            // 若声明了 sentinelOn,查 elementClass 里该字段的 size
            if (!this.sentinelOn.isEmpty()) {
                if (this.elementClass == void.class) {
                    throw new IllegalArgumentException(
                            "field '" + this.name + "' sentinelOn requires elementClass");
                }
                this.sentinelOnSize = lookupSentinelOnSize(this.elementClass, this.sentinelOn);
            } else {
                this.sentinelOnSize = 0;
            }
```

在私有 `FieldInfo(Field f, String name)`(@Payload)构造器加:
```java
            this.sentinelOn = "";
            this.sentinelValue = 0;
            this.sentinelOnSize = 0;
```

并新增 static 方法 `lookupSentinelOnSize`(在 FieldInfo 之后,ProtocolCodec 类中):
```java
    /** 查 elementClass 里 sentinelOn 字段的 size;字段不存在或 size<=0 抛异常。 */
    private static int lookupSentinelOnSize(Class<?> elementClass, String sentinelOn) {
        for (Field f : elementClass.getDeclaredFields()) {
            if (f.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolField.class)
                    && f.getName().equals(sentinelOn)) {
                int sz = f.getAnnotation(com.example.demo.protocol.annotation.ProtocolField.class).size();
                if (sz <= 0) {
                    throw new IllegalArgumentException(
                            "sentinelOn field '" + sentinelOn + "' in " + elementClass.getName()
                                    + " has no fixed size");
                }
                return sz;
            }
        }
        throw new IllegalArgumentException(
                "sentinelOn field '" + sentinelOn + "' not found in " + elementClass.getName());
    }
```

- [ ] **Step 5: readValue 的 LIST 分支加 sentinelOn 子分支**

找到 `case LIST ->` 分支(当前用 countField 循环),在循环前加 sentinelOn 判定:
```java
            case LIST -> {
                ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
                java.util.List<Object> list = new java.util.ArrayList<>();
                if (!fi.sentinelOn.isEmpty()) {
                    // 元素内 sentinel:peek sentinelOn 字段值,==sentinelValue 则停
                    while (true) {
                        long peek = cursor.peekBits(fi.sentinelOnSize);
                        if (peek == fi.sentinelValue) {
                            cursor.skipBits(fi.sentinelOnSize);  // 消费结束标记
                            break;
                        }
                        byte[] rest = cursor.remainingFromCursor();
                        Object elem = elementCodec.deserialize(rest, 0, rest.length);
                        list.add(elem);
                        cursor.skipBits((int) (serializeNested(elementCodec, elem).length * 8L));
                    }
                } else {
                    // count 驱动(Phase 2a 原逻辑)
                    int count = ctx.getInt(fi.countField);
                    list = new java.util.ArrayList<>(count);
                    for (int i = 0; i < count; i++) {
                        byte[] rest = cursor.remainingFromCursor();
                        Object elem = elementCodec.deserialize(rest, 0, rest.length);
                        list.add(elem);
                        cursor.skipBits((int) (serializeNested(elementCodec, elem).length * 8L));
                    }
                }
                yield list;
            }
```

> 注:`peekBits` 需给 BitCursor 加(偷看 N 位不推进)。见 Step 7。

- [ ] **Step 6: writeValue 的 LIST 分支加 sentinelOn 子分支**

找到 `writeValue` 的 `case LIST ->` 分支(当前用 countField 校验+写),在写完元素后加 sentinelOn 追加:
```java
            case LIST -> {
                @SuppressWarnings("unchecked")
                java.util.List<Object> list = (java.util.List<Object>) value;
                ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
                if (!fi.sentinelOn.isEmpty()) {
                    // 元素内 sentinel:无 count 校验,直接写元素 + 末尾追加 sentinelValue
                    for (Object elem : list) {
                        cursor.writeBytes(serializeNested(elementCodec, elem));
                    }
                    cursor.writeBits(fi.sentinelValue, fi.sentinelOnSize);  // 末尾结束标记
                } else {
                    // count 驱动(Phase 2a 原逻辑:校验 count==size + 写元素)
                    int declared = ctx.getInt(fi.countField);
                    if (declared != list.size()) {
                        throw new IllegalStateException(
                                "LIST field '" + fi.name + "': countField '" + fi.countField
                                        + "'=" + declared + " but list.size()=" + list.size());
                    }
                    for (Object elem : list) {
                        cursor.writeBytes(serializeNested(elementCodec, elem));
                    }
                }
            }
```

- [ ] **Step 7: BitCursor 加 peekBits**

在 `BitCursor.java` 加(类似 peekByte 但 N 位):
```java
    /** 偷看当前游标起的 size 位(不推进)。size 须 1..63。 */
    public long peekBits(int size) {
        if (size < 0 || size > 63) {
            throw new IllegalArgumentException("peekBits size must be 0..63, got " + size);
        }
        long value = 0;
        for (int i = 0; i < size; i++) {
            int absBit = baseByte * 8 + bitPos + i;
            int byteIdx = absBit / 8;
            if (byteIdx >= data.length) {
                return -1;  // 不足 size 位(到末尾)
            }
            int bitInByte = 7 - (absBit % 8);
            value = (value << 1) | ((data[byteIdx] >> bitInByte) & 1);
        }
        return value;
    }
```

- [ ] **Step 8: 运行测试确认通过**

Run: `./mvnw test -Dtest=DnsNameElementSentinelTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 1, Failures: 0`

- [ ] **Step 9: 全量回归**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 57 + 新 1 = 58)。DnsQuestion(count)/DnsNameSentinel(2b)/DhcpOptions(TLV)不受影响——sentinelOn 是 LIST 内的新子分支。

- [ ] **Step 10: 提交**

```bash
git add src/main/java/com/example/demo/protocol/annotation/ProtocolField.java src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/main/java/com/example/demo/protocol/core/BitCursor.java src/main/java/com/example/demo/protocol/DnsName.java src/test/java/com/example/demo/protocol/DnsNameElementSentinelTest.java
git commit -m "feat(codec): element-internal sentinel (sentinelOn/sentinelValue) for LIST"
```

---

## Task 3: 边界测试(空 QName / 读到末尾)

**Files:**
- Test: `src/test/java/com/example/demo/protocol/DnsNameSentinelEdgeTest.java`

- [ ] **Step 1: 写边界测试**

创建 `src/test/java/com/example/demo/protocol/DnsNameSentinelEdgeTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DnsNameSentinelEdgeTest {

    @Test
    void emptyDnsNameRoundTrips() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsName> codec = new ProtocolCodec<>(DnsName.class);

        // 仅 0x00 → 空 labels
        DnsName parsed = codec.deserialize(new byte[]{0x00});
        assertThat(parsed.getLabels()).isEmpty();

        // 空序列化 → 仅 0x00
        byte[] out = codec.serialize(new DnsName());
        assertThat(out).containsExactly(0x00);
    }

    @Test
    void noSentinelReadsToEnd() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsName> codec = new ProtocolCodec<>(DnsName.class);

        // 一个 label,无 0x00(读到末尾)
        DnsName parsed = codec.deserialize(new byte[]{0x03, 0x63, 0x6f, 0x6d});
        assertThat(parsed.getLabels()).hasSize(1);
        assertThat(parsed.getLabels().get(0).getContent()).containsExactly('c', 'o', 'm');
    }
}
```

- [ ] **Step 2: 运行确认通过**

Run: `./mvnw test -Dtest=DnsNameSentinelEdgeTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 2, Failures: 0`

> 注:`noSentinelReadsToEnd` 依赖 peekBits 在到末尾时返回 -1(不等于 sentinelValue 0)。若 peekBits 返回 -1 而非 0,循环应因"读不到完整 sentinelOn size"而结束。若测试失败,可能需在 readValue 的 sentinelOn 循环加"peek==-1 则 break(读到末尾)"。

- [ ] **Step 3: 提交**

```bash
git add src/test/java/com/example/demo/protocol/DnsNameSentinelEdgeTest.java
git commit -m "test(codec): DNS name element-sentinel edge cases (empty, no-sentinel)"
```

---

## Task 4: 注册期校验(互斥 + 字段不存在)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`
- Test: `src/test/java/com/example/demo/protocol/SentinelOnValidationTest.java`

- [ ] **Step 1: 写校验测试**

创建 `src/test/java/com/example/demo/protocol/SentinelOnValidationTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SentinelOnValidationTest {

    /** sentinelOn 与 countField 同时给 → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BothSentinelOnAndCount {
        @ProtocolField(order = 1, size = 8) private int n;
        @ProtocolField(order = 2, type = FieldType.LIST,
                countField = "n", elementClass = DnsLabel.class,
                sentinelOn = "length", sentinelValue = 0)
        private List<DnsLabel> labels;
    }

    @Test
    void rejectsSentinelOnWithCountField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BothSentinelOnAndCount.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sentinelOn");
    }

    /** sentinelOn 字段不存在 → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class UnknownSentinelOnField {
        @ProtocolField(order = 1, type = FieldType.LIST,
                elementClass = DnsLabel.class,
                sentinelOn = "ghost", sentinelValue = 0)
        private List<DnsLabel> labels;
    }

    @Test
    void rejectsUnknownSentinelOnField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(UnknownSentinelOnField.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ghost");
    }
}
```

- [ ] **Step 2: 运行确认**

Run: `./mvnw test -Dtest=SentinelOnValidationTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 字段不存在(ghost)应已抛(Task 2 的 lookupSentinelOnSize 校验);互斥校验需在 validateReferences 加。可能 1 失败。

- [ ] **Step 3: validateReferences 加互斥校验**

在 `validateReferences` 的 LIST 校验块(Phase 2a/2b)里,加 sentinelOn 互斥:
```java
            // sentinelOn 校验(Phase 2c2):与 countField/sentinel(2b)互斥
            if (!fi.sentinelOn.isEmpty()) {
                if (!fi.countField.isEmpty()) {
                    throw new IllegalArgumentException(
                            "LIST field '" + fi.name + "': sentinelOn and countField are mutually exclusive");
                }
                if (fi.sentinel >= 0) {
                    throw new IllegalArgumentException(
                            "LIST field '" + fi.name + "': sentinelOn and sentinel are mutually exclusive");
                }
            }
```

- [ ] **Step 4: 运行确认通过**

Run: `./mvnw test -Dtest=SentinelOnValidationTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 2, Failures: 0`

- [ ] **Step 5: 全量回归**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(58 + 2 + 2 = 62 左右)。DnsName(sentinelOn)合法,DnsQuestion(count)/DnsNameSentinel(2b)不受影响。

- [ ] **Step 6: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/SentinelOnValidationTest.java
git commit -m "feat(codec): validate sentinelOn mutual exclusion and field existence"
```

---

## Task 5: 全量验证 + 文档更新

- [ ] **Step 1: 全量测试**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 57 + ElementSentinel 1 + Edge 2 + Validation 2 = 62)

- [ ] **Step 2: 全量编译打包**

Run: `./mvnw package 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 更新 README**

在 `README.md` 的「### Phase 2c1」之后加一节「### Phase 2c2」,并把「### 仍未覆盖」里的元素内 sentinel 项移除/改写。

- [ ] **Step 4: 提交**

```bash
git add README.md
git commit -m "docs: Phase 2c2 element-internal sentinel"
```

---

## 完成标志

全部 Task 完成后:
- [ ] `./mvnw test` 全绿(62 个测试)
- [ ] `./mvnw package` 成功
- [ ] 真实 DNS QName round-trip:`[www,example,com]` → 标准字节 → 还原
- [ ] 空 QName(仅 0x00)→ 空 labels
- [ ] sentinelOn 互斥校验生效
- [ ] Phase 1~3a 全量回归不破
