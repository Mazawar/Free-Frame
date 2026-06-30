# 通用协议编解码引擎 Phase 2e — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给引擎加上位标志语义——标志位(TCP flags: SYN/ACK/FIN)用 `Set<Flag>` 表达,可读、可组合,引擎自动序列化(各 flag 的 mask 按位 OR)/反序列化(按位拆解成 Set)。

**Architecture:** 新增 `ProtocolFlag` 接口(`int mask()`)和 `@ProtocolField.flagClass`。**不加 FieldType 枚举值**——flag 字段走 Phase 1 的 INT 位读写,只在 `convertToFieldType`/`convertFromFieldType` 两个值转换方法里加 flag↔Set 映射分支(与 Phase 2d 的 enum 同构)。保留位(flagClass 未覆盖的位)忽略(C1 边界)。

**Tech Stack:** Java 25,Spring Boot 4.1,JUnit Jupiter 6 + AssertJ 3.27,Lombok。

**参考 spec:** `docs/superpowers/specs/2026-06-30-protocol-codec-phase2e-design.md`

**测试约定:** `./mvnw test -Dtest=XxxTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`(单类);全量 `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`。Git Bash on Windows。

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `core/ProtocolFlag.java` | flag 位掩码契约(`int mask()`) | 新建 |
| `annotation/ProtocolField.java` | 加 `flagClass` 属性(带默认值) | 修改 |
| `core/ProtocolCodec.java` | FieldInfo 读 flagClass;convert 层 flag 分支(Set↔EnumSet) | 修改 |
| `protocol/TcpFlag.java` | 试金石 flag 枚举(FIN/SYN/RST/PSH/ACK/URG) | 新建 |
| `protocol/TcpHeaderFlags.java` | 试金石实体(flags 字段用 Set) | 新建 |
| `test/.../FlagFieldTest.java` | 组合/单/空 flag round-trip + 保留位忽略 | 新建 |

包路径 `com.example.demo.protocol.*`。所有测试为纯 JUnit。

---

## Task 1: ProtocolFlag 接口

**Files:**
- Create: `src/main/java/com/example/demo/protocol/core/ProtocolFlag.java`

- [ ] **Step 1: 创建接口**

```java
package com.example.demo.protocol.core;

/** 位标志契约:实现此接口的 enum 可作为 @ProtocolField(flagClass=...) 的 flag 字段。 */
public interface ProtocolFlag {

    /** 该 flag 常量对应的位掩码(单 bit,如 SYN=0x02)。 */
    int mask();
}
```

- [ ] **Step 2: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolFlag.java
git commit -m "feat(codec): add ProtocolFlag contract interface"
```

---

## Task 2: @ProtocolField 加 flagClass 属性

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/annotation/ProtocolField.java`

- [ ] **Step 1: 加 flagClass 属性**

在 `ProtocolField.java` 的 `enumClass()` 之后,加一个属性:
```java
    /** 枚举字段:字段声明为 ProtocolEnum 接口类型时,用此指定具体 enum 类(扫描其常量)。 */
    Class<?> enumClass() default void.class;

    /** 位标志字段:字段类型为 Set,用此指定具体 flag enum 类。 */
    Class<?> flagClass() default void.class;
```

- [ ] **Step 2: 编译确认(老字段不受影响,flagClass 有默认值 void.class)**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/annotation/ProtocolField.java
git commit -m "feat(codec): add flagClass to @ProtocolField for bit flags"
```

---

## Task 3: ProtocolCodec flag 支持(核心)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`

这是 Phase 2e 核心。三处改动:FieldInfo 读 flagClass;convertToFieldType 加 flag 反序列化分支(需加 flagClass 参数);convertFromFieldType 加 flag 序列化分支。

- [ ] **Step 1: 写失败测试**

创建 `src/test/java/com/example/demo/protocol/FlagFieldTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.core.ProtocolFlag;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class FlagFieldTest {

    public enum TcpFlag implements ProtocolFlag {
        FIN(0x01), SYN(0x02), RST(0x04), PSH(0x08), ACK(0x10), URG(0x20);
        private final int m;
        TcpFlag(int m) { this.m = m; }
        @Override public int mask() { return m; }
    }

    @Data
    @ProtocolPacket(port = 0)
    public static class FlagPacket {
        @ProtocolField(order = 1, size = 8, flagClass = TcpFlag.class)
        private Set<TcpFlag> flags;
    }

    @Test
    void roundTripsCombinedFlags() {
        ProtocolCodec<FlagPacket> codec = new ProtocolCodec<>(FlagPacket.class);

        FlagPacket original = new FlagPacket();
        original.setFlags(EnumSet.of(TcpFlag.SYN, TcpFlag.ACK));  // 0x02 | 0x10 = 0x12

        byte[] out = codec.serialize(original);
        assertThat(out).containsExactly(0x12);

        FlagPacket parsed = codec.deserialize(out);
        assertThat(parsed.getFlags()).containsExactlyInAnyOrder(TcpFlag.SYN, TcpFlag.ACK);
    }

    @Test
    void roundTripsSingleAndEmptyFlags() {
        ProtocolCodec<FlagPacket> codec = new ProtocolCodec<>(FlagPacket.class);

        // 单 flag
        FlagPacket single = new FlagPacket();
        single.setFlags(EnumSet.of(TcpFlag.SYN));
        assertThat(codec.serialize(single)).containsExactly(0x02);
        assertThat(codec.deserialize(new byte[]{0x02}).getFlags()).containsExactly(TcpFlag.SYN);

        // 空 flag
        FlagPacket empty = new FlagPacket();
        empty.setFlags(EnumSet.noneOf(TcpFlag.class));
        assertThat(codec.serialize(empty)).containsExactly(0x00);
        assertThat(codec.deserialize(new byte[]{0x00}).getFlags()).isEmpty();
    }

    @Test
    void reservedBitsAreIgnored() {
        ProtocolCodec<FlagPacket> codec = new ProtocolCodec<>(FlagPacket.class);

        // 0x52 = SYN(0x02) | ACK(0x10) | 保留位(0x40,flagClass 未定义)
        FlagPacket parsed = codec.deserialize(new byte[]{0x52});
        assertThat(parsed.getFlags()).containsExactlyInAnyOrder(TcpFlag.SYN, TcpFlag.ACK);  // 0x40 忽略

        // 序列化回去:已知 flag 零丢失,保留位丢失 → 0x12(声明的 C1 行为)
        byte[] reserialized = codec.serialize(parsed);
        assertThat(reserialized).containsExactly(0x12);
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `./mvnw test -Dtest=FlagFieldTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(Set 字段当 int 处理,反序列化赋不进 Set 字段)

- [ ] **Step 3: FieldInfo 加 flagClass 字段**

在 `ProtocolCodec.java` 的 `FieldInfo` 内部类里,加 `final Class<?> flagClass;`。
- 在 `FieldInfo(Field f)` 构造器里加:`this.flagClass = ann.flagClass();`
- 在私有 `FieldInfo(Field f, String name)`(@Payload 用)构造器里加:`this.flagClass = void.class;`

- [ ] **Step 4: convertFromFieldType 加 flag 序列化分支**

找到 `convertFromFieldType(Object value)`(static)。在 `ProtocolEnum` 分支之后加 flag 分支:
```java
    private static long convertFromFieldType(Object value) {
        if (value instanceof ProtocolEnum e) {
            return e.value();
        }
        // flag 字段:Set<ProtocolFlag> → 各 mask 按位 OR
        if (value instanceof java.util.Set<?> set) {
            long orResult = 0;
            for (Object o : set) {
                if (o instanceof ProtocolFlag f) {
                    orResult |= f.mask();
                }
            }
            return orResult;
        }
        if (value == null) {
            return 0;
        }
        if (value instanceof Number n) {
            return n.longValue();
        }
        return 0;
    }
```

- [ ] **Step 5: convertToFieldType 加 flag 反序列化分支(需加 flagClass 参数)**

把 `convertToFieldType` 签名加 `flagClass` 参数,并在 enum 分支之后加 flag 分支:
```java
    private static Object convertToFieldType(Class<?> type, long val, boolean unsigned, Class<?> enumClass, Class<?> flagClass) {
        // enum 字段:优先用注解的 enumClass,否则用字段 type(若它本身就是具体 enum)
        Class<?> effectiveEnumType = (enumClass != null && enumClass != void.class) ? enumClass : type;
        if (ProtocolEnum.class.isAssignableFrom(effectiveEnumType) && Enum.class.isAssignableFrom(effectiveEnumType)) {
            return enumFromValue(effectiveEnumType, (int) val);
        }
        // flag 字段:Set<ProtocolFlag>,按位拆解成 EnumSet(保留位忽略)
        if (flagClass != null && flagClass != void.class && java.util.Set.class.isAssignableFrom(type)) {
            return flagsFromValue(flagClass, (int) val);
        }
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
```

并新增静态辅助 `flagsFromValue`(放在 `enumFromValue` 之后):
```java
    /** 把整数按位拆解成 EnumSet;保留位(flagClass 未覆盖的位)忽略(C1)。 */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static Object flagsFromValue(Class<?> flagClass, int value) {
        Object[] constants = flagClass.getEnumConstants();
        java.util.EnumSet result = java.util.EnumSet.noneOf((Class<Enum>) flagClass);
        if (constants != null) {
            for (Object c : constants) {
                if (((ProtocolFlag) c).mask() != 0 && (value & ((ProtocolFlag) c).mask()) != 0) {
                    result.add(c);
                }
            }
        }
        return result;
    }
```

- [ ] **Step 6: 更新 readValue 调用处,传 flagClass**

找到 `readValue` 里的 `convertToFieldType(fi.field.getType(), cursor.readBits(size), type == FieldType.UNSIGNED, fi.enumClass);` 这一行,改成:
```java
            case INT, UNSIGNED -> convertToFieldType(fi.field.getType(), cursor.readBits(size), type == FieldType.UNSIGNED, fi.enumClass, fi.flagClass);
```

- [ ] **Step 7: 运行测试确认通过**

Run: `./mvnw test -Dtest=FlagFieldTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 3, Failures: 0`

- [ ] **Step 8: 全量回归(确认 Phase 1+2a+2b+2d 未破)**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 44 + 新 3 = 47)。enum 字段不受影响(flag 走 Set 路径,enum 走 enumClass 路径)。

- [ ] **Step 9: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/FlagFieldTest.java
git commit -m "feat(codec): bit flag support in convert layer (Set<Flag>)"
```

---

## Task 4: TcpFlag + TcpHeaderFlags 实体

**Files:**
- Create: `src/main/java/com/example/demo/protocol/TcpFlag.java`
- Create: `src/main/java/com/example/demo/protocol/TcpHeaderFlags.java`

- [ ] **Step 1: 创建 TcpFlag enum**

```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolFlag;

/** TCP 标志位(RFC 793)。mask = 该 flag 在 flags 字段中的位掩码。 */
public enum TcpFlag implements ProtocolFlag {
    FIN(0x01),
    SYN(0x02),
    RST(0x04),
    PSH(0x08),
    ACK(0x10),
    URG(0x20);

    private final int m;

    TcpFlag(int m) {
        this.m = m;
    }

    @Override
    public int mask() {
        return m;
    }
}
```

- [ ] **Step 2: 创建 TcpHeaderFlags 实体**

```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import lombok.Data;
import lombok.ToString;

import java.util.EnumSet;
import java.util.Set;

/**
 * TCP flags 字段(简化):用 Set<TcpFlag> 表达。
 * 实际 TCP flags 占 9 位(含保留位/NS/CWR/ECE),此处用 8 位示例;
 * 保留位(mask 未覆盖)反序列化时忽略。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class TcpHeaderFlags {

    @ProtocolField(order = 1, size = 8, flagClass = TcpFlag.class)
    private Set<TcpFlag> flags = EnumSet.noneOf(TcpFlag.class);
}
```

- [ ] **Step 3: 编译确认 + 复用 FlagFieldTest 的逻辑验证**

Task 3 的 FlagFieldTest 已经验证 flag 机制。这里创建的 TcpFlag/TcpHeaderFlags 是给用户参考的「正式实体」。编译确认:
Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

(可选:可加一个简单的 TcpHeaderFlagsTest,但 FlagFieldTest 已覆盖机制,此处省略以避免重复。)

- [ ] **Step 4: 提交**

```bash
git add src/main/java/com/example/demo/protocol/TcpFlag.java src/main/java/com/example/demo/protocol/TcpHeaderFlags.java
git commit -m "feat(protocol): TcpFlag enum and TcpHeaderFlags specimen"
```

---

## Task 5: 全量验证 + 文档更新

- [ ] **Step 1: 全量测试**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 44 + FlagField 3 = 47)

- [ ] **Step 2: 全量编译打包**

Run: `./mvnw package 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 更新 README**

在 `README.md` 的「### Phase 2d」之后,加一节「### Phase 2e」,并把「### 仍未覆盖」里的位标志项移除:
```markdown
### Phase 2e(本版本新增)

- **位标志 `Set<Flag>`** —— 标志位(TCP flags: SYN/ACK/FIN)用 `Set` 表达,可读、可组合。序列化时各 flag 的 mask 按位 OR;反序列化按位拆解成 `EnumSet`。保留位(flag 未定义的位)忽略。

示例:

```java
public enum TcpFlag implements ProtocolFlag {
    FIN(0x01), SYN(0x02), ACK(0x10);
    private final int m;
    TcpFlag(int m) { this.m = m; }
    public int mask() { return m; }
}

@ProtocolField(order=6, size=8, flagClass=TcpFlag.class)
private Set<TcpFlag> flags;   // SYN+ACK → 0x12;读 0x12 → EnumSet.of(SYN,ACK)
```

### 仍未覆盖(后续 Phase)

- 元素内字段级 sentinel(如 DNS 的「label 长度=0 表示结束」)
- 异质 TLV(type → 子结构分派,如 TCP/DHCP Options)
- 复杂条件(位掩码 / `&&`)
- 校验和 / CRC 钩子(IPv4/TCP/UDP 校验和、伪首部)
- 流重组 / 分片重组(过程性,留钩子)
```

- [ ] **Step 4: 提交**

```bash
git add README.md
git commit -m "docs: document Phase 2e bit flag semantics"
```

---

## 完成标志

全部 Task 完成后:
- [ ] `./mvnw test` 全绿(47 个测试)
- [ ] `./mvnw package` 成功
- [ ] 组合 flag:SYN+ACK → 0x12 → SYN+ACK
- [ ] 单/空 flag round-trip
- [ ] 保留位忽略:0x52 → SYN+ACK(丢 0x40)→ serialize 0x12(声明的 C1 行为)
- [ ] Phase 1+2a+2b+2d 全量回归不破
