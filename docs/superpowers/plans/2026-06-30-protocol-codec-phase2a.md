# 通用协议编解码引擎 Phase 2a — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给 Phase 1 的协议编解码引擎加上「count 驱动的同质重复数组」(`type=LIST` + `countField` + `elementClass`),让"重复 N 次相同结构"的协议(如 DNS QName)能用实体类定义。

**Architecture:** 集合用 `List<X>` + `elementClass`,每个元素本身是一个 Phase 1 实体类(`@ProtocolPacket` + `@ProtocolField`),其结构由已有机制描述——**复用而非重造**。外层 LIST 只负责「重复 N 次 + 推进游标」。元素必须自定边界(注册期强制);序列化时要求 `countField == list.size()` 否则报错。

**Tech Stack:** Java 25,Spring Boot 4.1,JUnit Jupiter 6 + AssertJ 3.27,Lombok。

**参考 spec:** `docs/superpowers/specs/2026-06-30-protocol-codec-phase2a-design.md`

**测试约定:** 命令统一 `./mvnw test -Dtest=XxxTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`(单类,`tr` 去除非 ASCII 注释字符以免 grep 报错);全量 `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`。Git Bash on Windows。

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `core/FieldType.java` | 加 `LIST` 枚举值 | 修改 |
| `annotation/ProtocolField.java` | 加 `countField`/`elementClass` 属性(带默认值) | 修改 |
| `core/BitCursor.java` | 加 `remainingFromCursor()` + `skipBits()`(LIST 反序列化用) | 修改 |
| `core/ProtocolCodec.java` | LIST 分支(反序列化按 count 重复、序列化校验一致性)+ 类型推断 + 注册校验 | 修改 |
| `protocol/DnsLabel.java` | LIST 元素实体(1字节length + 变长content) | 新建 |
| `protocol/DnsQuestion.java` | 含 count 字段 + List 字段的顶层实体 | 新建 |
| `test/.../CodecListTest.java` | LIST round-trip + count 一致性 | 新建 |
| `test/.../CodecListValidationTest.java` | 元素边界校验 + countField 引用合法性 | 新建 |

包路径 `com.example.demo.protocol.*`。所有测试为纯 JUnit,无 Spring 上下文。

---

## Task 1: FieldType 加 LIST 枚举值

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/FieldType.java`

- [ ] **Step 1: 加 LIST**

把 `FieldType.java` 的枚举体改为(在 NESTED 后加 LIST):
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
    NESTED,
    /** count 驱动的同质重复数组:元素是 elementClass 实体,个数由 countField 决定。 */
    LIST
}
```

- [ ] **Step 2: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`(老代码不用 LIST,加个枚举值不破坏任何东西)

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/FieldType.java
git commit -m "feat(codec): add LIST to FieldType for count-driven repeating arrays"
```

---

## Task 2: @ProtocolField 加 countField / elementClass

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/annotation/ProtocolField.java`

- [ ] **Step 1: 加两个属性**

在 `ProtocolField.java` 的 `charset()` 之后追加两个属性(均带默认值):
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

    /** count 驱动(LIST 用):引用元素个数字段名。 */
    String countField() default "";

    /** LIST 元素的实体类型(LIST 时必填)。 */
    Class<?> elementClass() default void.class;
}
```

- [ ] **Step 2: 编译确认(MyProtocol/Ipv4Header 不受影响,因新属性有默认值)**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/annotation/ProtocolField.java
git commit -m "feat(codec): add countField/elementClass to @ProtocolField for LIST"
```

---

## Task 3: DnsLabel + DnsQuestion 实体

**Files:**
- Create: `src/main/java/com/example/demo/protocol/DnsLabel.java`
- Create: `src/main/java/com/example/demo/protocol/DnsQuestion.java`

- [ ] **Step 1: 创建 DnsLabel(LIST 元素,自定边界)**

```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * DNS label:1 字节长度 + 变长内容。用作 LIST 元素。
 * 自定边界:content 由 lengthField="length" 定长度,不会「吃剩余字节」。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DnsLabel {

    @ProtocolField(order = 1, size = 8)
    private int length;

    @ProtocolField(order = 2, type = FieldType.BYTES, lengthField = "length")
    private byte[] content;

    public DnsLabel() {
        this.content = new byte[0];
    }

    /** 便捷构造:从字符串生成 label。 */
    public DnsLabel(String s) {
        byte[] b = s.getBytes();
        this.length = b.length;
        this.content = b;
    }
}
```

- [ ] **Step 2: 创建 DnsQuestion(含 count + List)**

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
 * DNS Question 段(count 驱动变体):labelCount 个 label。
 * 注意:真实 DNS 用 0x00 结束标记,非 count;此处是 Phase 2a 的 count 驱动子集。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DnsQuestion {

    @ProtocolField(order = 1, size = 8)
    private int labelCount;

    @ProtocolField(order = 2, type = FieldType.LIST,
            countField = "labelCount", elementClass = DnsLabel.class)
    private List<DnsLabel> labels = new ArrayList<>();
}
```

- [ ] **Step 3: 编译确认(此时 LIST 还没实现,但实体本身能编译;编解码会在 Task 4 实现)**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 4: 提交**

```bash
git add src/main/java/com/example/demo/protocol/DnsLabel.java src/main/java/com/example/demo/protocol/DnsQuestion.java
git commit -m "feat(protocol): add DnsLabel and DnsQuestion entities for LIST"
```

---

## Task 4: ProtocolCodec 实现 LIST 分支(核心)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`
- Modify: `src/main/java/com/example/demo/protocol/core/BitCursor.java`(加 `remainingFromCursor`/`skipBits`,见 Step 6)

这是 Phase 2a 的核心。涉及四处改动:`FieldInfo`(读新属性)、`effectiveType`(List→LIST 推断)、`resolveSize`/读写循环(LIST 分支)、注册校验。

- [ ] **Step 1: 写失败测试(LIST round-trip + count 一致性)**

创建 `src/test/java/com/example/demo/protocol/CodecListTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CodecListTest {

    @Test
    void roundTripsCountDrivenList() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsQuestion> codec = new ProtocolCodec<>(DnsQuestion.class);

        DnsQuestion q = new DnsQuestion();
        q.setLabelCount(3);
        q.getLabels().add(new DnsLabel("www"));      // 03 77 77 77
        q.getLabels().add(new DnsLabel("example"));  // 07 65 78 61 6d 70 6c 65
        q.getLabels().add(new DnsLabel("com"));      // 03 63 6f 6d

        byte[] out = codec.serialize(q);
        // 标准字节(RFC 1035 label 编码):1字节count + 各label
        assertThat(out).containsExactly(
                0x03,                                             // labelCount
                0x03, 0x77, 0x77, 0x77,                           // "www"
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,   // "example"
                0x03, 0x63, 0x6f, 0x6d);                          // "com"

        DnsQuestion parsed = codec.deserialize(out);
        assertThat(parsed.getLabelCount()).isEqualTo(3);
        assertThat(parsed.getLabels()).hasSize(3);
        assertThat(parsed.getLabels().get(0).getContent()).containsExactly('w', 'w', 'w');
        assertThat(parsed.getLabels().get(1).getContent()).containsExactly('e', 'x', 'a', 'm', 'p', 'l', 'e');
        assertThat(parsed.getLabels().get(2).getContent()).containsExactly('c', 'o', 'm');
    }

    @Test
    void rejectsCountSizeMismatchOnSerialize() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsQuestion> codec = new ProtocolCodec<>(DnsQuestion.class);

        DnsQuestion q = new DnsQuestion();
        q.setLabelCount(3);                  // 声明 3
        q.getLabels().add(new DnsLabel("a")); // 实际 1 → 不一致

        assertThatThrownBy(() -> codec.serialize(q))
                .isInstanceOf(RuntimeException.class)  // serialize 包装成 RuntimeException
                .hasMessageContaining("countField");
    }

    @Test
    void handlesZeroCountList() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsQuestion> codec = new ProtocolCodec<>(DnsQuestion.class);

        DnsQuestion q = new DnsQuestion();
        q.setLabelCount(0);  // 空 List

        byte[] out = codec.serialize(q);
        assertThat(out).containsExactly(0x00);  // 仅 count 字节

        DnsQuestion parsed = codec.deserialize(out);
        assertThat(parsed.getLabelCount()).isEqualTo(0);
        assertThat(parsed.getLabels()).isEmpty();
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `./mvnw test -Dtest=CodecListTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(LIST 还未实现;serialize 会报 "cannot resolve size" 或 List 字段被当成未知类型)

- [ ] **Step 3: 改 FieldInfo —— 读新属性**

在 `ProtocolCodec.java` 的 `FieldInfo` 内部类中(找到 `FieldInfo(Field f)` 构造和字段声明区),新增三个字段并在构造器里读取。把 `FieldInfo` 改成:
```java
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
        final String countField;       // 新增
        final Class<?> elementClass;   // 新增

        /** 常规字段构造:读取 @ProtocolField 的全部属性。 */
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
            this.countField = ann.countField();
            this.elementClass = ann.elementClass();
        }

        /** @Payload 字段构造:无 @ProtocolField,仅需字段引用(其余属性用占位值)。 */
        static FieldInfo forPayload(Field f) {
            return new FieldInfo(f, f.getName());
        }

        private FieldInfo(Field f, String name) {
            this.field = f;
            this.name = name;
            this.order = -1;
            this.size = -1;
            this.type = FieldType.BYTES;
            this.lengthField = "";
            this.lengthUnit = LengthUnit.BYTES;
            this.presentIf = "";
            this.charset = "UTF-8";
            this.countField = "";
            this.elementClass = void.class;
        }
    }
```

- [ ] **Step 4: 改 effectiveType —— List 推断为 LIST**

在 `effectiveType(FieldInfo fi)` 方法里,在 `@ProtocolPacket 实体 → NESTED` 判断之前,加一条 List 推断。把 `effectiveType` 改成:
```java
    private FieldType effectiveType(FieldInfo fi) {
        if (fi.type != FieldType.INT) {
            return fi.type; // 显式指定
        }
        Class<?> t = fi.field.getType();
        if (java.util.List.class.isAssignableFrom(t)) {
            return FieldType.LIST;
        }
        if (t == byte[].class) {
            return FieldType.BYTES;
        }
        if (t == String.class) {
            return FieldType.STRING;
        }
        if (!t.isPrimitive() && !Number.class.isAssignableFrom(t)
                && t.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolPacket.class)) {
            return FieldType.NESTED;
        }
        return FieldType.INT;
    }
```

- [ ] **Step 5: 改 resolveSize —— LIST 分支**

在 `resolveSize` 方法里,**在最前面**(钩子之前)加 LIST 分支。LIST 的「size」用于序列化算总位数 = 所有元素 serialize 后的总 bit 数。把 `resolveSize` 开头改为:
```java
    private long resolveSize(FieldInfo fi, Object obj, FieldContext ctx, boolean deserialize, int remainingBits) throws Exception {
        // 0. LIST:count 驱动,元素个数 = countField 值
        if (effectiveType(fi) == FieldType.LIST) {
            return listTotalBits(fi, obj, ctx, deserialize);
        }
        // 1. 钩子优先
        if (obj instanceof DynamicSize ds) {
            ... // 原样不动
```

并在 `resolveSize` 之后新增私有方法 `listTotalBits`:
```java
    /**
     * 计算 LIST 字段的总位数(供 resolveSize 用)。
     * 序列化路径:逐个 serialize 元素累加;反序列化路径:同样逐个 serialize(此时元素尚未读出,
     * 但本方法仅在「序列化算总位数」与「反序列化读元素前」被调用——反序列化时实际不经过 resolveSize,
     * 而是直接在 deserialize 主循环里处理 LIST,见 readValue)。
     */
    private long listTotalBits(FieldInfo fi, Object obj, FieldContext ctx, boolean deserialize) throws Exception {
        fi.field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.List<Object> list = (java.util.List<Object>) fi.field.get(obj);
        if (list == null) {
            return 0;
        }
        ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
        long total = 0;
        for (Object elem : list) {
            total += serializeNested(elementCodec, elem).length * 8L;
        }
        return total;
    }
```

> 注:反序列化时 LIST 的实际读取不靠 resolveSize(元素逐个从游标读),而靠 `readValue` 的 LIST 分支(下一步)。`listTotalBits` 主要服务序列化端的「算总位数」两遍循环。

- [ ] **Step 6: 改 readValue —— LIST 反序列化分支**

在 `readValue` 的 switch 里加 LIST case。注意:`readValue` 没有 `rawData` 参数,但 LIST 反序列化时元素 size 未知(取决于元素自身内容),需要把元素 codec 接到「从游标当前位置起的字节」上。为此先给 `BitCursor` 加一个 `remainingFromCursor()` 方法(见下)。

先给 `BitCursor` 加方法(修改 `src/main/java/com/example/demo/protocol/core/BitCursor.java`,在 `bitOffset()` 附近):
```java
    /** 返回从当前游标位置(按字节对齐)起的剩余字节片段。游标必须字节对齐。 */
    public byte[] remainingFromCursor() {
        if (bitPos % 8 != 0) {
            throw new IllegalStateException("remainingFromCursor requires byte-aligned cursor, bitPos=" + bitPos);
        }
        int bytePos = baseByte + bitPos / 8;
        return java.util.Arrays.copyOfRange(data, bytePos, data.length);
    }
```

然后 `readValue` 加 LIST case:
```java
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
            case LIST -> {
                // count 驱动:逐个反序列化元素,游标按元素实际消耗推进
                int count = ctx.getInt(fi.countField);
                ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
                java.util.List<Object> list = new java.util.ArrayList<>(count);
                for (int i = 0; i < count; i++) {
                    // 元素从游标当前位置(字节对齐)起读;元素自定边界,只消耗它该消耗的
                    byte[] rest = cursor.remainingFromCursor();
                    Object elem = elementCodec.deserialize(rest, 0, rest.length);
                    list.add(elem);
                    // 推进游标 = 该元素 serialize 后的字节数 * 8(元素字节对齐,故是 8 的倍数)
                    int consumedBits = (int) (serializeNested(elementCodec, elem).length * 8L);
                    cursor.skipBits(consumedBits);
                }
                yield list;
            }
        };
    }
```

并给 `BitCursor` 加 `skipBits`(在 `remainingFromCursor` 附近):
```java
    /** 推进游标 n 位(不读取,仅移动)。 */
    public void skipBits(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("skipBits n must be >= 0, got " + n);
        }
        bitPos += n;
    }
```

- [ ] **Step 7: 改 writeValue —— LIST 序列化分支**

在 `writeValue` 的 switch 里加 LIST case:
```java
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
                cursor.writeBytes(serializeNested(nested, value));
            }
            case LIST -> {
                @SuppressWarnings("unchecked")
                java.util.List<Object> list = (java.util.List<Object>) value;
                // 一致性校验(选项 C):count == list.size()
                int declared = ctx.getInt(fi.countField);
                if (declared != list.size()) {
                    throw new IllegalStateException(
                            "LIST field '" + fi.name + "': countField '" + fi.countField
                                    + "'=" + declared + " but list.size()=" + list.size());
                }
                ProtocolCodec<?> elementCodec = codecFor(fi.elementClass);
                for (Object elem : list) {
                    cursor.writeBytes(serializeNested(elementCodec, elem));
                }
            }
        }
    }
```

- [ ] **Step 8: 运行测试确认通过**

Run: `./mvnw test -Dtest=CodecListTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 3, Failures: 0`

- [ ] **Step 9: 全量回归(确认 Phase 1 未破)**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 23 + 新 3 = 26)

- [ ] **Step 10: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/main/java/com/example/demo/protocol/core/BitCursor.java src/test/java/com/example/demo/protocol/CodecListTest.java
git commit -m "feat(codec): implement LIST branch (count-driven repeating arrays)"
```

---

## Task 5: 注册期校验(countField 引用 + 元素自定边界)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`
- Test: `src/test/java/com/example/demo/protocol/CodecListValidationTest.java`

- [ ] **Step 1: 写失败测试**

创建 `src/test/java/com/example/demo/protocol/CodecListValidationTest.java`:
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

class CodecListValidationTest {

    /** 无自定边界的元素:最后一个字段变长且无 lengthField/countField → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BadElement {
        @ProtocolField(order = 1, size = 8) private int mark;
        @ProtocolField(order = 2, type = FieldType.BYTES) private byte[] rest; // 吃剩余!无边界
    }

    @Data
    @ProtocolPacket(port = 0)
    public static class BadListContainer {
        @ProtocolField(order = 1, size = 8) private int n;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "n", elementClass = BadElement.class)
        private List<BadElement> items;
    }

    @Test
    void rejectsElementWithoutSelfBoundary() {
        // 元素 BadElement 最后字段 rest 无 size/lengthField 且非 LIST → 注册期抛
        assertThatThrownBy(() -> new ProtocolCodec<>(BadListContainer.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("boundary");
    }

    /** countField 引用不存在的字段 → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class UnknownCountContainer {
        @ProtocolField(order = 1, size = 8) private int realCount;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "ghost", elementClass = DnsLabel.class)
        private List<DnsLabel> items;
    }

    @Test
    void rejectsUnknownCountField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(UnknownCountContainer.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ghost");
    }

    /** countField 前向引用(order 更大)→ 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class ForwardCountContainer {
        @ProtocolField(order = 1, type = FieldType.LIST, countField = "n", elementClass = DnsLabel.class)
        private List<DnsLabel> items;
        @ProtocolField(order = 2, size = 8) private int n; // order 比 items 大 → 前向引用
    }

    @Test
    void rejectsForwardCountField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(ForwardCountContainer.class))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `./mvnw test -Dtest=CodecListValidationTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(校验未实现,构造器不抛)

- [ ] **Step 3: 扩展 validateReferences —— 加 LIST 校验**

在 `validateReferences` 方法里,对每个字段增加 LIST 相关校验。把 `validateReferences` 末尾(for 循环内,在 presentIf 校验之后)追加 LIST 校验块:
```java
            // LIST 校验:用户显式声明了 elementClass 即视为 LIST(也覆盖 type=LIST 显式写法)
            if (fi.elementClass != void.class) {
                // countField 必须引用真实、更早的字段
                if (fi.countField.isEmpty()) {
                    throw new IllegalArgumentException(
                            "LIST field '" + fi.name + "' missing countField");
                }
                Integer refOrder = nameToOrder.get(fi.countField);
                if (refOrder == null) {
                    throw new IllegalArgumentException(
                            "LIST field '" + fi.name + "' countField references unknown field '" + fi.countField + "'");
                }
                if (refOrder >= fi.order) {
                    throw new IllegalArgumentException(
                            "LIST field '" + fi.name + "' countField references '" + fi.countField
                                    + "' which is not earlier in order (forward ref forbidden)");
                }
                // elementClass 必须是 @ProtocolPacket 实体
                if (!fi.elementClass.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolPacket.class)) {
                    throw new IllegalArgumentException(
                            "LIST field '" + fi.name + "' elementClass " + fi.elementClass.getName()
                                    + " is not a @ProtocolPacket entity");
                }
                // 元素必须自定边界
                validateElementBoundary(fi.elementClass);
            }
```

注意:`validateReferences` 是 static,用 `fi.elementClass != void.class` 判定 LIST(用户显式声明 elementClass 即视为 LIST;`type=LIST` 也总是配 elementClass)。不需要额外的 static 推断方法。

- [ ] **Step 4: 加 validateElementBoundary 静态方法**

在 `validateReferences` 之后新增:
```java
    /**
     * 校验 LIST 元素能否自定边界:最后一个 @ProtocolField 字段必须能定长度
     * (有 size>0、或有 lengthField、或本身是 LIST/LIST 元素靠 countField)。
     * 否则元素会「吃剩余字节」,在 count 驱动场景下无法正确分割。
     */
    private static void validateElementBoundary(Class<?> elementClass) {
        java.lang.reflect.Field[] fields = elementClass.getDeclaredFields();
        java.lang.reflect.Field lastProtocolField = null;
        for (java.lang.reflect.Field f : fields) {
            if (f.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolField.class)) {
                lastProtocolField = f;
            }
        }
        if (lastProtocolField == null) {
            return; // 无字段,边界平凡
        }
        com.example.demo.protocol.annotation.ProtocolField ann =
                lastProtocolField.getAnnotation(com.example.demo.protocol.annotation.ProtocolField.class);
        boolean selfBounded = ann.size() > 0
                || !ann.lengthField().isEmpty()
                || ann.elementClass() != void.class;  // LIST 元素靠自己的 countField 定边界
        if (!selfBounded) {
            throw new IllegalArgumentException(
                    "LIST element " + elementClass.getName() + " last field '"
                            + lastProtocolField.getName() + "' has no self-boundary "
                            + "(no size/lengthField and not LIST): count-driven LIST cannot split it");
        }
    }
```

- [ ] **Step 5: 运行测试确认通过**

Run: `./mvnw test -Dtest=CodecListValidationTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 3, Failures: 0`

- [ ] **Step 6: 全量回归**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(26 + 3 = 29)。**注意确认 DnsQuestion(DnsLabel 作元素)仍合法**——DnsLabel 最后字段 content 有 `lengthField="length"`,应通过校验。

- [ ] **Step 7: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/CodecListValidationTest.java
git commit -m "feat(codec): validate LIST countField refs and element self-boundary"
```

---

## Task 6: 全量验证 + 文档更新

- [ ] **Step 1: 全量测试**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: `Tests run: 29, Failures: 0, Errors: 0`(原 23 + LIST 3 + 校验 3)

- [ ] **Step 2: 全量编译打包**

Run: `./mvnw package 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 更新 README,记录 Phase 2a 能力**

在 `README.md` 的「### Phase 1 未覆盖(后续 Phase)」列表里,把已完成的项标记。找到该列表,改为:
```markdown
### Phase 2a(本版本新增)

- **count 驱动的同质重复数组** —— `type=LIST` + `countField` + `elementClass`,`List<X>` 字段,元素是另一个实体类(如 DNS label)。

### 仍未覆盖(后续 Phase)

- length 驱动的数组 / 结束标记驱动(如真实 DNS 的 0x00、DHCP 的 0xFF)
- 异质 TLV(type → 子结构分派,如 TCP/DHCP Options)
- 复杂条件(位掩码 / `&&`)
- 校验和 / CRC 钩子
- 流重组 / 分片重组
```

- [ ] **Step 4: 提交**

```bash
git add README.md
git commit -m "docs: document Phase 2a LIST capability"
```

---

## 完成标志

全部 Task 完成后:
- [ ] `./mvnw test` 全绿(29 个测试)
- [ ] `./mvnw package` 成功
- [ ] DNS Question round-trip:count=3 → 标准字节 → 还原 List 相等
- [ ] count↔size 不一致 → 序列化抛异常(选项 C)
- [ ] 元素无自定边界 → 注册期抛异常(选项 A)
- [ ] Phase 1 全量回归(Ipv4Parity/MyProtocol 等)未破
