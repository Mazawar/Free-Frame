# 通用协议编解码引擎 — Phase 2d 设计(枚举语义)

- 状态:草案(待用户复审)
- 日期:2026-06-30
- 试金石协议:IPv4 protocol 字段(6=TCP, 17=UDP)
- 范围:`ProtocolEnum` 接口 + 未知值兜底,让协议里的「语义数字」用枚举表达

---

## 1. 背景与目标

### 1.1 现状(Phase 1 + 2a + 2b 之后)

引擎已支持位字段、长度引用、嵌套、条件、字符串、count/sentinel/length 驱动的变长与集合。但协议里的**语义数字**(IP protocol: 6=TCP/17=UDP,DNS type,HTTP method 等)只能用裸 `int` 表达——代码里只看到数字 `17`,可读性差、易错(写错 16 不会报错)。

### 1.2 Phase 2d 目标

让协议里的「整数字段 ↔ 语义枚举」自动映射:用户 enum 实现一个接口,实体字段直接用 enum 类型,引擎自动序列化/反序列化。读到未知值(协议演进,新分配的号)不中断,存原始数字。

### 1.3 Phase 2d 不做(留后续)

| 不含 | 留给 |
|---|---|
| 位标志(`Set<Flag>` 语义,SYN+ACK 组合) | 后续 phase |
| 枚举字符串名映射(DNS type 名 → 值) | 后续 |
| 校验和/CRC | Phase 3 |
| 元素内 sentinel / 异质 TLV | Phase 2c |

剪裁依据:枚举(整体一个值)与标志位(多独立位可组合)本质不同,标志位需 `Set<Flag>` 语义与位运算,单独打磨。Phase 2d 先做简单、高频、价值明确的枚举。

---

## 2. 关键设计抉择

### 2.1 枚举值映射:显式 `value()` 方法 + 约定接口(路线 2 / 子方案 2a)

Java `enum` 的 `ordinal()`(声明顺序)无法表达协议的不连续值(UDP=17),故用显式数值方法。提供接口 `ProtocolEnum { int value(); }`,用户 enum 实现它:

```java
public enum IpProtocol implements ProtocolEnum {
    ICMP(1), TCP(6), UDP(17);
    private final int v;
    IpProtocol(int v) { this.v = v; }
    @Override public int value() { return v; }
}
```

引擎序列化:`((ProtocolEnum) enumVal).value()` → 写 bit。反序列化:读 bit 得整数 → 转 enum。明确契约,不靠反射猜方法名。

### 2.2 未知值处理:不抛异常,存原始数字(策略 B / 落地 B2-simplified)

协议不断演进,enum 没覆盖的值(如 OSPF=89)高频出现。Phase 2d 不抛异常(否则一个未知值整包解析失败,抓包工具不可接受),而是:

引擎遍历 `enum.values()` 找 `value()==N` 的常量;**找不到时,存一个引擎提供的 `UnknownEnumValue` 占位对象**(携带原始 int + 原始 enum 类型)。用户 enum 无需自己写兜底常量,保持简单。

`UnknownEnumValue` 也实现 `ProtocolEnum`,其 `value()` 返回存的原始 int → **序列化时信息零丢失**(读 89 出来,写 89 回去)。

---

## 3. 注解 DSL(零增量!)

**关键发现**:Phase 2d 不需要新注解属性,也不需要新 `FieldType` 枚举值。枚举字段就是「读 N 位整数,转成 enum」——**位读写完全复用 Phase 1 的 INT 机制**,只在值转换层加 enum↔int 映射。

引擎通过 `effectiveType`(Java 类型推断)识别:字段类型是 `Enum` 子类且实现 `ProtocolEnum` → 走 enum 转换路径。

> `FieldType` 不加 `ENUM`。enum 字段在 `effectiveType` 里被识别为「INT 位读写 + enum 值转换」。这样最干净——`FieldType` 保持纯结构语义,enum 是「值类型层」的事。

---

## 4. 新增类型

### 4.1 `ProtocolEnum` 接口(新建)

```java
package com.example.demo.protocol.core;

/** 枚举字段契约:实现此接口的 enum 可作为 @ProtocolField 字段类型。 */
public interface ProtocolEnum {
    /** 该枚举常量对应的整数值(协议里的 wire 值)。 */
    int value();
}
```

### 4.2 `UnknownEnumValue` 占位类(新建)

```java
package com.example.demo.protocol.core;

/** 未知枚举值的兜底占位:反序列化遇 enum 未覆盖的整数时使用。序列化返回存的原始 int,信息零丢失。 */
public final class UnknownEnumValue implements ProtocolEnum {
    private final int rawValue;
    private final Class<? extends Enum<?>> enumType;

    public UnknownEnumValue(int rawValue, Class<? extends Enum<?>> enumType) {
        this.rawValue = rawValue;
        this.enumType = enumType;
    }
    @Override public int value() { return rawValue; }
    public Class<? extends Enum<?>> enumType() { return enumType; }
    @Override public String toString() { return "Unknown(" + enumType.getSimpleName() + "=" + rawValue + ")"; }
}
```

---

## 5. 编解码流程(增量,极简)

### 5.1 识别 enum(在 convert 层,不动 effectiveType/FieldType)

**重要:`effectiveType` 不加 enum 分支,`FieldType` 不加 ENUM。** enum 字段的 `effectiveType` 仍返回 INT(位读写走 INT 那套)。enum 的处理发生在 `readValue`/`writeValue` 调用 `convertToFieldType`/`convertFromFieldType` 时——这两个 convert 方法判断**字段类型**是否 `Enum` 子类且实现 `ProtocolEnum`,是则走 enum 转换,否则走原 INT 转换。

判定辅助:在 `convertToFieldType`/`convertFromFieldType` 里用 `fi.field.getType()` 判断(需传入 field 类型,而非依赖 effectiveType 返回值)。

### 5.2 反序列化(转换层)

读到整数 N,若字段类型是 `ProtocolEnum` enum:
```
遍历 enumClass.getEnumConstants() 找 value()==N 的:
    找到 → 该常量
    找不到 → new UnknownEnumValue(N, enumClass)
```

### 5.3 序列化(转换层)

值是 `ProtocolEnum`(含 `UnknownEnumValue`)→ 取 `.value()` 写 bit。`UnknownEnumValue.value()` 返回原始 int → 信息零丢失。

---

## 6. 向后兼容(硬指标)

| Phase 1/2a/2b 代码 | Phase 2d 后 |
|---|---|
| `Ipv4Header`(`private int protocol`)、MyProtocol、所有现有 int 字段 | 零改动,全绿 |
| enum 是新增能力 | 老的 int 字段不碰;只有字段类型声明为 `ProtocolEnum` enum 才走新路径 |
| `@ProtocolField` / `FieldType` | 完全不变(不加注解、不加枚举值) |

**关键兼容点**:`effectiveType` 只在字段类型**是 enum 且实现 ProtocolEnum** 时走 enum 路径,普通 int 走原 INT 路径。Phase 2d 纯增量。

---

## 7. 验收标本:IPv4 protocol 字段

```java
public enum IpProtocol implements ProtocolEnum {
    ICMP(1), TCP(6), UDP(17);
    private final int v;
    IpProtocol(int v) { this.v = v; }
    @Override public int value() { return v; }
}

@Data @ProtocolPacket(port = 0)
public class Ipv4HeaderWithEnum {
    @ProtocolField(order=9, size=8) private IpProtocol protocol;
    // ... 其余字段(此处仅展示 protocol)
}
```

- `protocol=UDP` → serialize → 字节含 `0x11`(17)
- `0x11` → deserialize → `protocol == IpProtocol.UDP`
- `0x59`(89,enum 没有)→ deserialize → `UnknownEnumValue`(value=89)→ serialize → `0x59`(零丢失)

---

## 8. 测试与验收策略

| 测试 | 验证 |
|---|---|
| `EnumFieldTest` | 已知值 round-trip:`protocol=UDP` → `0x11` → 还原 `IpProtocol.UDP` |
| `EnumUnknownValueTest` | 未知值:`0x59`(89)→ `UnknownEnumValue`(value=89)→ serialize 回 `0x59` |
| `EnumParityTest` | 真实 IP 包 vs pcap4j:`getProtocol()` 一致(都 UDP/17) |
| **Phase 1+2a+2b 全量回归** | Ipv4Parity、MyProtocol、DnsQuestion、sentinel 等全绿 |

---

## 9. Phase 2d 交付清单

- [ ] `ProtocolEnum` 接口(`int value()`)
- [ ] `UnknownEnumValue` 占位类(存原始 int + enumClass,实现 ProtocolEnum)
- [ ] `effectiveType`:识别 `Enum & ProtocolEnum` 字段
- [ ] `convertToFieldType`/`convertFromFieldType`:enum↔int 转换 + 兜底
- [ ] `IpProtocol` enum + `Ipv4HeaderWithEnum` 实体
- [ ] 3 类测试 + Phase 1+2a+2b 回归
