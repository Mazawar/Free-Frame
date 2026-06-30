# 通用协议编解码引擎 Phase 2d — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给引擎加上枚举语义——协议里的「语义数字」(IP protocol: 17=UDP)用 `enum` 表达,引擎自动序列化/反序列化,未知值不中断。

**Architecture:** 新增 `ProtocolEnum` 接口(`int value()`)和 `UnknownEnumValue` 占位类。**不加注解、不加 FieldType 枚举值**——enum 字段走 Phase 1 的 INT 位读写,只在 `convertToFieldType`/`convertFromFieldType` 两个值转换方法里加 enum↔int 映射分支。读到未知值返回 `UnknownEnumValue`(携带原始 int),序列化返回该 int,信息零丢失。

**Tech Stack:** Java 25,Spring Boot 4.1,JUnit Jupiter 6 + AssertJ 3.27,Lombok。

**参考 spec:** `docs/superpowers/specs/2026-06-30-protocol-codec-phase2d-design.md`

**测试约定:** `./mvnw test -Dtest=XxxTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`(单类);全量 `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`。Git Bash on Windows。

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `core/ProtocolEnum.java` | 枚举契约接口(`int value()`) | 新建 |
| `core/UnknownEnumValue.java` | 未知值兜底占位(存原始 int + enumClass) | 新建 |
| `core/ProtocolCodec.java` | convert 层加 enum 分支(序列化取 value,反序列化遍历+兜底) | 修改 |
| `protocol/IpProtocol.java` | 试金石枚举(ICMP/TCP/UDP) | 新建 |
| `protocol/Ipv4HeaderWithEnum.java` | 试金石实体(protocol 字段用 enum) | 新建 |
| `test/.../EnumFieldTest.java` | 已知值 round-trip | 新建 |
| `test/.../EnumUnknownValueTest.java` | 未知值 round-trip(零丢失) | 新建 |
| `test/.../EnumParityTest.java` | 真实 IP 包 vs pcap4j parity | 新建 |

包路径 `com.example.demo.protocol.*`。所有测试为纯 JUnit。

---

## Task 1: ProtocolEnum 接口

**Files:**
- Create: `src/main/java/com/example/demo/protocol/core/ProtocolEnum.java`

- [ ] **Step 1: 创建接口**

```java
package com.example.demo.protocol.core;

/** 枚举字段契约:实现此接口的 enum 可作为 @ProtocolField 字段类型。 */
public interface ProtocolEnum {

    /** 该枚举常量对应的整数值(协议里的 wire 值)。 */
    int value();
}
```

- [ ] **Step 2: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolEnum.java
git commit -m "feat(codec): add ProtocolEnum contract interface"
```

---

## Task 2: UnknownEnumValue 占位类

**Files:**
- Create: `src/main/java/com/example/demo/protocol/core/UnknownEnumValue.java`

- [ ] **Step 1: 创建占位类**

```java
package com.example.demo.protocol.core;

/**
 * 未知枚举值的兜底占位:反序列化遇 enum 未覆盖的整数时使用。
 * 实现 ProtocolEnum,序列化返回存的原始 int,信息零丢失。
 */
public final class UnknownEnumValue implements ProtocolEnum {

    private final int rawValue;
    private final Class<? extends Enum<?>> enumType;

    public UnknownEnumValue(int rawValue, Class<? extends Enum<?>> enumType) {
        this.rawValue = rawValue;
        this.enumType = enumType;
    }

    @Override
    public int value() {
        return rawValue;
    }

    public Class<? extends Enum<?>> enumType() {
        return enumType;
    }

    @Override
    public String toString() {
        return "Unknown(" + enumType.getSimpleName() + "=" + rawValue + ")";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UnknownEnumValue that)) return false;
        return rawValue == that.rawValue && enumType.equals(that.enumType);
    }

    @Override
    public int hashCode() {
        return rawValue * 31 + enumType.hashCode();
    }
}
```

> 注:加 equals/hashCode 是为了让「未知值 round-trip 后相等」可断言(测试需要)。

- [ ] **Step 2: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/UnknownEnumValue.java
git commit -m "feat(codec): add UnknownEnumValue placeholder for unknown enum wire values"
```

---

## Task 3: ProtocolCodec convert 层加 enum 分支(核心)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`

这是 Phase 2d 核心。当前 `convertToFieldType` 和 `convertFromFieldType` 都是 static。enum 判定需要字段类型(Class),`convertToFieldType` 已有 `type` 参数;`convertFromFieldType` 当前签名是 `(Object value)`,enum 序列化只需 `value` 本身(`instanceof ProtocolEnum`),不需要字段类型。故两者都可在现有签名内处理。

- [ ] **Step 1: 写失败测试**

创建 `src/test/java/com/example/demo/protocol/EnumFieldTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.core.ProtocolEnum;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EnumFieldTest {

    public enum IpProtocol implements ProtocolEnum {
        ICMP(1), TCP(6), UDP(17);
        private final int v;
        IpProtocol(int v) { this.v = v; }
        @Override public int value() { return v; }
    }

    @Data
    @ProtocolPacket(port = 0)
    public static class ProtoPacket {
        @ProtocolField(order = 1, size = 8) private IpProtocol protocol;
    }

    @Test
    void roundTripsKnownEnumValue() {
        ProtocolCodec<ProtoPacket> codec = new ProtocolCodec<>(ProtoPacket.class);

        ProtoPacket original = new ProtoPacket();
        original.setProtocol(IpProtocol.UDP);  // 17 = 0x11

        byte[] out = codec.serialize(original);
        assertThat(out).containsExactly(0x11);

        ProtoPacket parsed = codec.deserialize(out);
        assertThat(parsed.getProtocol()).isEqualTo(IpProtocol.UDP);
    }

    @Test
    void roundTripsAllEnumValues() {
        ProtocolCodec<ProtoPacket> codec = new ProtocolCodec<>(ProtoPacket.class);
        for (IpProtocol p : IpProtocol.values()) {
            ProtoPacket original = new ProtoPacket();
            original.setProtocol(p);
            byte[] out = codec.serialize(original);
            assertThat(out).containsExactly((byte) p.value());
            assertThat(codec.deserialize(out).getProtocol()).isEqualTo(p);
        }
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `./mvnw test -Dtest=EnumFieldTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(enum 字段当 int 处理,反序列化赋不进 IpProtocol 字段,或类型转换异常)

- [ ] **Step 3: convertFromFieldType 加 enum 序列化分支**

找到 `convertFromFieldType(Object value)`(static)。在 `if (value == null)` 之前加 enum 分支:
```java
    private static long convertFromFieldType(Object value) {
        if (value instanceof ProtocolEnum e) {
            return e.value();
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
(`UnknownEnumValue` 也实现 ProtocolEnum,故序列化未知值返回原始 int,零丢失。)

- [ ] **Step 4: convertToFieldType 加 enum 反序列化分支**

找到 `convertToFieldType(Class<?> type, long val, boolean unsigned)`(static)。在方法体最前面加 enum 判定(优先于数字分支):
```java
    private static Object convertToFieldType(Class<?> type, long val, boolean unsigned) {
        // enum 字段:type 是 ProtocolEnum 的 enum
        if (ProtocolEnum.class.isAssignableFrom(type) && Enum.class.isAssignableFrom(type)) {
            return enumFromValue(type, (int) val);
        }
        if (unsigned) {
            ... // 原样不动
```

并新增 static 辅助方法 `enumFromValue`(放在 convertToFieldType 之后):
```java
    /** 把整数转成 enum 常量;找不到匹配值返回 UnknownEnumValue(携带原始 int)。 */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static Object enumFromValue(Class<?> enumType, int value) {
        Object[] constants = enumType.getEnumConstants();
        if (constants != null) {
            for (Object c : constants) {
                if (((ProtocolEnum) c).value() == value) {
                    return c;
                }
            }
        }
        return new UnknownEnumValue(value, (Class<? extends Enum<?>>) enumType);
    }
```

- [ ] **Step 5: 运行测试确认通过**

Run: `./mvnw test -Dtest=EnumFieldTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 2, Failures: 0`

- [ ] **Step 6: 全量回归(确认 Phase 1+2a+2b 未破)**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 39 + 新 2 = 41)。普通 int 字段走原 INT 路径,不受影响。

- [ ] **Step 7: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/EnumFieldTest.java
git commit -m "feat(codec): enum field support in convert layer (known values)"
```

---

## Task 4: 未知值 round-trip 测试

**Files:**
- Test: `src/test/java/com/example/demo/protocol/EnumUnknownValueTest.java`

- [ ] **Step 1: 写测试**

创建 `src/test/java/com/example/demo/protocol/EnumUnknownValueTest.java`(自带 enum + packet,避免跨测试类引用):
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.core.ProtocolEnum;
import com.example.demo.protocol.core.UnknownEnumValue;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EnumUnknownValueTest {

    /** 只定义 1/6/17,89 未覆盖。 */
    public enum Proto implements ProtocolEnum {
        ICMP(1), TCP(6), UDP(17);
        private final int v;
        Proto(int v) { this.v = v; }
        @Override public int value() { return v; }
    }

    @Data
    @ProtocolPacket(port = 0)
    public static class Pkt {
        @ProtocolField(order = 1, size = 8) private Proto protocol;
    }

    @Test
    void unknownValueDeserializesToPlaceholder() {
        ProtocolCodec<Pkt> codec = new ProtocolCodec<>(Pkt.class);

        // 89 = OSPF,enum 里没有
        Pkt parsed = codec.deserialize(new byte[]{(byte) 89});
        Object protocol = parsed.getProtocol();
        assertThat(protocol).isInstanceOf(UnknownEnumValue.class);
        assertThat(((UnknownEnumValue) protocol).value()).isEqualTo(89);
    }

    @Test
    void unknownValueRoundTripsWithZeroLoss() {
        ProtocolCodec<Pkt> codec = new ProtocolCodec<>(Pkt.class);

        // 读 89 → UnknownEnumValue → 再序列化 → 仍是 89(零丢失)
        Pkt parsed = codec.deserialize(new byte[]{(byte) 89});
        byte[] reserialized = codec.serialize(parsed);
        assertThat(reserialized).containsExactly((byte) 89);
    }
}
```

- [ ] **Step 2: 运行确认通过**

Run: `./mvnw test -Dtest=EnumUnknownValueTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 2, Failures: 0`(Task 3 已实现兜底,这里验证它)

- [ ] **Step 3: 提交**

```bash
git add src/test/java/com/example/demo/protocol/EnumUnknownValueTest.java
git commit -m "test(codec): unknown enum value round-trips with zero loss"
```

---

## Task 5: IpProtocol + Ipv4HeaderWithEnum 实体 + parity 验收

**Files:**
- Create: `src/main/java/com/example/demo/protocol/IpProtocol.java`
- Create: `src/main/java/com/example/demo/protocol/Ipv4HeaderWithEnum.java`
- Test: `src/test/java/com/example/demo/protocol/EnumParityTest.java`

- [ ] **Step 1: 创建 IpProtocol enum**

```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolEnum;

/** IP 协议号(RFC 790 子集)。值 = 协议在 IP 头里的 wire 值。 */
public enum IpProtocol implements ProtocolEnum {
    ICMP(1),
    TCP(6),
    UDP(17);

    private final int v;

    IpProtocol(int v) {
        this.v = v;
    }

    @Override
    public int value() {
        return v;
    }
}
```

- [ ] **Step 2: 创建 Ipv4HeaderWithEnum 实体**

```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import lombok.Data;
import lombok.ToString;

/**
 * IPv4 头的 protocol 字段用 enum 表达(而非裸 int)。
 * 仅含 protocol 字段用于 parity 验收(对比 pcap4j 的 getProtocol())。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class Ipv4HeaderWithEnum {

    @ProtocolField(order = 1, size = 8)
    private IpProtocol protocol;
}
```

- [ ] **Step 3: 写 parity 测试**

创建 `src/test/java/com/example/demo/protocol/EnumParityTest.java`:
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

class EnumParityTest {

    @Test
    void ourEnumProtocolMatchesPcap4j() throws Exception {
        // pcap4j 构造 IP 包(protocol=UDP)
        IpV4Packet pcapPkt = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)   // = 17
                .srcAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.1"))
                .dstAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.2"))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .build();

        // protocol 字节在 IP 头第 10 字节(offset 9)
        byte protocolByte = pcapPkt.getHeader().getRawData()[9];

        ProtocolCodec<Ipv4HeaderWithEnum> codec = new ProtocolCodec<>(Ipv4HeaderWithEnum.class);
        Ipv4HeaderWithEnum ours = codec.deserialize(new byte[]{protocolByte});

        // parity:我们的 enum 值 == pcap4j 的 protocol(都 UDP/17)
        assertThat(ours.getProtocol()).isEqualTo(IpProtocol.UDP);
        assertThat(ours.getProtocol().value()).isEqualTo(pcapPkt.getHeader().getProtocol().value() & 0xFF);
    }
}
```

- [ ] **Step 4: 运行确认通过**

Run: `./mvnw test -Dtest=EnumParityTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 1, Failures: 0`

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/protocol/IpProtocol.java src/main/java/com/example/demo/protocol/Ipv4HeaderWithEnum.java src/test/java/com/example/demo/protocol/EnumParityTest.java
git commit -m "feat(protocol): IpProtocol enum + parity vs pcap4j"
```

---

## Task 6: 全量验证 + 文档更新

- [ ] **Step 1: 全量测试**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 39 + EnumField 2 + EnumUnknown 2 + EnumParity 1 = 44)

- [ ] **Step 2: 全量编译打包**

Run: `./mvnw package 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 更新 README**

在 `README.md` 的「### Phase 2b」之后,加一节「### Phase 2d」,并把「### 仍未覆盖」里的枚举项移除:
```markdown
### Phase 2d(本版本新增)

- **枚举语义** —— 字段类型用 `enum`(实现 `ProtocolEnum`):协议里的语义数字(IP protocol 17=UDP)自动映射,可读、类型安全。未知值不中断,存原始数字(零丢失)。

示例:

```java
public enum IpProtocol implements ProtocolEnum {
    ICMP(1), TCP(6), UDP(17);
    private final int v;
    IpProtocol(int v) { this.v = v; }
    public int value() { return v; }
}

@ProtocolField(order=9, size=8) private IpProtocol protocol;  // 而非 int
```

### 仍未覆盖(后续 Phase)

- 位标志(`Set<Flag>` 语义,SYN+ACK 组合)
- 元素内字段级 sentinel(如 DNS 的「label 长度=0 表示结束」)
- 异质 TLV(type → 子结构分派,如 TCP/DHCP Options)
- 复杂条件(位掩码 / `&&`)
- 校验和 / CRC 钩子(IPv4/TCP/UDP 校验和、伪首部)
- 流重组 / 分片重组
```

- [ ] **Step 4: 提交**

```bash
git add README.md
git commit -m "docs: document Phase 2d enum semantics"
```

---

## 完成标志

全部 Task 完成后:
- [ ] `./mvnw test` 全绿(44 个测试)
- [ ] `./mvnw package` 成功
- [ ] 已知枚举值:UDP → 0x11 → UDP(含 pcap4j parity)
- [ ] 未知值:89 → UnknownEnumValue(value=89)→ 89(零丢失)
- [ ] Phase 1+2a+2b 全量回归不破
