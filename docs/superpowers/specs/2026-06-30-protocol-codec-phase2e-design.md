# 通用协议编解码引擎 — Phase 2e 设计(位标志 Set<Flag>)

- 状态:草案(待用户复审)
- 日期:2026-06-30
- 试金石协议:TCP flags(SYN/ACK/FIN 组合)
- 范围:`ProtocolFlag` 接口 + `flagClass` 注解,让标志位用 `Set<Flag>` 表达,可读、可组合

---

## 1. 背景与目标

### 1.1 现状(Phase 1 + 2a + 2b + 2d 之后)

引擎已支持位字段、长度引用、嵌套、条件、字符串、count/sentinel/length 驱动变长与集合、枚举语义。但协议里的**位标志**(TCP flags:SYN/ACK/FIN 多位独立、可组合)只能用裸 `int`(如 `0x12`)表达——不直观、判断时要写位运算(`(flags & 0x02) != 0`)。

Phase 2d 的枚举解决「整体一个值」(17=UDP);位标志是**多位独立、可组合**(`SYN=0x02 | ACK=0x10`),本质不同,需独立机制。

### 1.2 Phase 2e 目标

让标志位字段用 `Set<Flag>` 表达:序列化时各 flag 的 mask 按位 OR;反序列化时读出的整数按位拆解成 Set。可读(`flags.contains(SYN)`)、可组合(`EnumSet.of(SYN, ACK)`)。

### 1.3 Phase 2e 不做(留后续)

| 不含 | 留给 |
|---|---|
| 保留位零丢失(C2 双字段方案) | 后续 |
| 元素内 sentinel / 异质 TLV | Phase 2c |
| 校验和/CRC | Phase 3 |

**诚实边界(C1)**:Phase 2e 的 Set round-trip 对**已知 flag 零丢失**,但**保留位**(flag enum 未定义的位)会被忽略——读 `0x52`(SYN+ACK+保留0x40)→ `EnumSet.of(SYN,ACK)`,序列化回 `0x12`(丢0x40)。绝大多数场景只关心已知 flag,保留位无意义;真要零丢失后续加 rawInt 透传。

---

## 2. 关键设计抉择

### 2.1 flag 用显式 `mask()` 方法 + `ProtocolFlag` 接口(路线 1)

flag enum 实现 `ProtocolFlag { int mask(); }`,每个常量显式声明位掩码。与 Phase 2d 的 `ProtocolEnum.value()` 完全同构:

```java
public enum TcpFlag implements ProtocolFlag {
    FIN(0x01), SYN(0x02), RST(0x04), PSH(0x08), ACK(0x10), URG(0x20);
    private final int m;
    TcpFlag(int m) { this.m = m; }
    @Override public int mask() { return m; }
}
```

不用 ordinal(位序不连续)、不用注解(enum 常量注解笨拙)。

### 2.2 字段用 `Set<Flag>` 类型

字段声明为 `Set<TcpFlag>`,配 `flagClass` 注解指定具体 flag enum。引擎序列化:`flags` 各元素 mask() 按位 OR → 写 bit;反序列化:读 bit 得整数 → 遍历 flagClass,`(N & mask) != 0` 加入 EnumSet。

### 2.3 保留位处理:C1 忽略

反序列化只组装已定义 flag;保留位(flagClass 未覆盖的位)丢弃。round-trip 对已知 flag 零丢失,保留位会丢。见 §1.3 边界。

---

## 3. 注解 DSL(零 FieldType 增量,同构 Phase 2d)

**关键**:位标志位读写复用 Phase 1 的 INT 机制,只在值转换层加 flag↔Set 映射。**`FieldType` 不加新枚举值。**

引擎通过字段类型(`Set`)+ `flagClass` 注解识别 flag 字段 → 走 flag 转换路径。

| 新增 | 说明 |
|---|---|
| `ProtocolFlag` 接口(`int mask()`) | flag 位掩码契约(同 ProtocolEnum) |
| `@ProtocolField.flagClass` | 指定具体 flag enum 类(同 enumClass) |
| (无新 FieldType 枚举值) | flag 走 INT 位读写,convert 层转换 |

---

## 4. 新增类型

### 4.1 `ProtocolFlag` 接口(新建)

```java
package com.example.demo.protocol.core;

/** 位标志契约:实现此接口的 enum 可作为 @ProtocolField(flagClass=...) 的 flag 字段。 */
public interface ProtocolFlag {
    /** 该 flag 常量对应的位掩码(单 bit,如 SYN=0x02)。 */
    int mask();
}
```

### 4.2 `@ProtocolField.flagClass` 属性(改注解)

```java
/** 位标志字段:指定具体 flag enum 类(字段类型为 Set)。 */
Class<?> flagClass() default void.class;
```

---

## 5. 编解码流程(增量,极简)

### 5.1 识别 flag(在 convert 层,不动 FieldType)

flag 字段位读写走 INT。enum/flag 的区分在 `convertToFieldType`/`convertFromFieldType`:
- 字段类型是 `Set` 且有 `flagClass` → flag 转换
- 否则 → 原 INT / enum 路径

> flag 字段的 `size` 不限位数(示例用 8 位,但 TCP flags 实际 9 位亦可)。size 决定读写多少位,mask 决定哪些位对应已知 flag;二者独立。

> 实现注记:`convertToFieldType`/`convertFromFieldType` 当前签名为 `(Class<?> type, long val, boolean unsigned, Class<?> enumClass)`。flag 需要额外的 `flagClass` 参数——实现时给这两个方法加 `Class<?> flagClass` 参数(或合并为一个 `flagClass` 复用),并更新 `readValue`/`writeValue` 调用处传入 `fi.flagClass`。

### 5.2 反序列化(转换层)

读到整数 N,若字段是 flag 字段:
```
result = EnumSet.noneOf(flagClass)
遍历 flagClass.getEnumConstants():
    if (N & mask) != 0 → result.add(flag)
返回 result(保留位忽略)
```

### 5.3 序列化(转换层)

值是 `Set<ProtocolFlag>`:
```
orResult = 0
for flag in set: orResult |= flag.mask()
写 orResult 到 bit
```

---

## 6. 向后兼容(硬指标)

| Phase 1/2a/2b/2d 代码 | Phase 2e 后 |
|---|---|
| `Ipv4Header`、MyProtocol、所有现有字段 | 零改动,全绿 |
| flag 是新增能力 | 老字段不碰;只有 `Set` 类型 + `flagClass` 才走 flag 路径 |
| `@ProtocolField` 老属性 | 全保留;新增 `flagClass` 带默认值 `void.class` |
| `FieldType` 老枚举值 | 不变 |

**关键兼容点**:flag 路径只在字段类型是 `Set` 且声明 `flagClass` 时触发。普通 int、enum 字段不受影响。Phase 2e 纯增量。

---

## 7. 验收标本:TCP flags

```java
public enum TcpFlag implements ProtocolFlag {
    FIN(0x01), SYN(0x02), RST(0x04), PSH(0x08), ACK(0x10), URG(0x20);
    private final int m;
    TcpFlag(int m) { this.m = m; }
    @Override public int mask() { return m; }
}

@Data @ProtocolPacket(port = 0)
public class TcpHeaderFlags {
    @ProtocolField(order = 1, size = 8, flagClass = TcpFlag.class)
    private Set<TcpFlag> flags;
}
```

- `EnumSet.of(SYN, ACK)` → serialize → `0x12`(0x02|0x10)→ deserialize → `EnumSet.of(SYN, ACK)`
- `0x52`(SYN+ACK+保留0x40)→ deserialize → `EnumSet.of(SYN, ACK)`(0x40 忽略)

---

## 8. 测试与验收策略

| 测试 | 验证 |
|---|---|
| `FlagFieldTest` | 组合:`EnumSet.of(SYN,ACK)` → `0x12` → 还原 |
| `FlagSingleEmptyTest` | 单 flag(`0x02`)、空 flag(`0x00`)round-trip |
| `FlagReservedBitTest` | 保留位忽略:`0x52` → `EnumSet.of(SYN,ACK)` → serialize `0x12`(丢0x40,声明的 C1 行为) |
| **Phase 1+2a+2b+2d 全量回归** | Ipv4Parity、MyProtocol、DnsQuestion、sentinel、enum 等全绿 |

---

## 9. Phase 2e 交付清单

- [ ] `ProtocolFlag` 接口(`int mask()`)
- [ ] `@ProtocolField.flagClass` 属性(带默认值 void.class)
- [ ] `FieldInfo` 读 flagClass
- [ ] `convertToFieldType`/`convertFromFieldType`:flag 分支(Set↔EnumSet)
- [ ] `TcpFlag` enum + `TcpHeaderFlags` 实体
- [ ] 3 类测试 + Phase 1+2a+2b+2d 回归
