# 通用协议编解码引擎 — Phase 2a 设计(同质重复数组)

- 状态:草案(待用户复审)
- 日期:2026-06-30
- 试金石协议:DNS Question 段(Qname,count 驱动简化变体)
- 范围:`type=LIST` + `countField` + `elementClass`,支持「count 驱动的同质重复数组」

---

## 1. 背景与目标

### 1.1 现状(Phase 1 之后)

Phase 1 已实现:位字段、长度引用(`lengthField`)、协议嵌套(NESTED)、条件字段(`presentIf`)、字符串编码、`DynamicSize` 钩子。但仍不支持**「重复不定个数的字段」**——这是 8 类短板里卡住最多协议的一类(DNS QName 的多 label、固定结构重复 N 次等)。

### 1.2 Phase 2a 目标

支持 **count 驱动的同质重复数组**:一个数量字段(N)决定某字段重复 N 次,每次结构相同;每个元素用 Phase 1 已有的「实体类 + 注解」机制描述结构。

### 1.3 Phase 2a 不做(留后续)

| 不含 | 留给 |
|---|---|
| 异质 TLV(type → 子结构分派,如 TCP/DHCP Options) | Phase 2c |
| length 驱动的数组(按总字节数结束) | Phase 2b |
| 结束标记驱动(如 DNS 的 0x00、DHCP 的 0xFF) | Phase 2b |
| 枚举/标志位语义 | Phase 2b |
| 校验和/CRC | Phase 3 |

剪裁依据:把"重复字段"里最难、最依赖运行时分派的异质 TLV 单独切出去;先把最干净的 count 语义做扎实。结束后用户可定义「有显式 count 字段」的任意同质数组协议,但不能解析真实 DNS(DNS 用结束标记 0x00,非 count 驱动)。

---

## 2. 关键设计抉择

### 2.1 集合用 `List<X>` + `elementClass`(路线 2)

每个元素本身是一个 Phase 1 实体类(`@ProtocolPacket` + `@ProtocolField`),其结构由已有机制描述,**复用而非重造**。外层 LIST 只负责「重复 N 次 + 推进游标」。

- ✅ 元素结构零重造(用 Phase 1 实体类机制)
- ✅ `countField` 与 Phase 1 的 `lengthField` 同族(声明式字段引用),认知一致
- ✅ 天然延伸到 Phase 2c 异质 TLV(届时 elementClass 之外加 type 分派表)
- 否决:`byte[][]`(表达不了变长元素结构)、纯钩子(违背「定义即实体类」初心)

### 2.2 元素必须自定边界(选项 A,注册期强制)

LIST 的每个元素反序列化时,引擎按「重复 N 次」调用 elementCodec。若元素是「吃剩余字节」的变长实体,它不知道在哪停,会吞掉后续所有字节。

**硬约束**:elementClass 必须能自定边界——要么全定长,要么靠自己的 `lengthField`/`countField` 定边界。检测:elementClass 的最后一个字段若是变长(无 lengthField/countField/无 size)→ 注册期抛异常。

「最后一个元素吃剩余」是 length 驱动语义,属 Phase 2b,Phase 2a 不支持。

### 2.3 countField 双向一致性(选项 C)

- **反序列化**:以报文里的 count 为准(那是真实数据,读 N 个元素)
- **序列化**:要求 `ctx.getInt(countField) == list.size()`,不一致抛异常(不搞隐式回填)

理由:count 字段可能参与校验和/被别处引用,隐式改它的值是危险的;要求用户自洽,问题暴露在表面。与 Phase 1「声明式、可预测、不搞魔法」哲学一致。

---

## 3. 注解 DSL 增量

### 3.1 `@ProtocolField` 新增属性(均带默认值,Phase 1 零改动)

| 属性 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `countField` | String | `""` | count 驱动:引用元素个数字段名 |
| `elementClass` | Class<?> | `void.class` | 元素的实体类型(LIST 时必填) |

### 3.2 `FieldType` 新增枚举值

```java
public enum FieldType { INT, UNSIGNED, BYTES, STRING, NESTED, LIST }
```

### 3.3 判定优先级(每字段)

```
type == LIST  → countField 必填,elementClass 必填,走 LIST 分支(独立于 size/lengthField/钩子)
否则          → 沿用 Phase 1:hook > lengthField > size
```

### 3.4 类型推断(扩展 Phase 1 的 `effectiveType`)

Phase 1 按字段 Java 类型推断:byte[]→BYTES、String→STRING、@ProtocolPacket 实体→NESTED。Phase 2a 增补一条:**字段 Java 类型是 `java.util.List`(或其子类)→ 推断为 `LIST`**。此时要求注解显式给出 `countField` + `elementClass`(注册期校验,缺失则抛异常)。也可显式写 `type=LIST`。

---

## 4. 编解码流程

### 4.1 反序列化(LIST 分支)

```
if type == LIST:
    count = ctx.getInt(countField)               // count 在前(注册期校验 order 更小)
    list = new ArrayList(count)
    loop i in 0..count-1:
        elementCodec = codecFor(elementClass)
        consumedBefore = cursor.bitOffset()
        elem = elementCodec.deserialize(rawData, 当前字节偏移, 剩余字节)
        list.add(elem)
        cursor.advance(elementCodec 实际消耗位数)  // = serialize(elem).length * 8
    obj.<listField> = list
```

每个元素用「自己的 codec」从游标当前位置读起;元素内部(如 DnsLabel 的 content 用 lengthField="length")自己消耗正确字节数,游标自动推进。

### 4.2 序列化(LIST 分支,先校验一致性)

```
if type == LIST:
    if ctx.getInt(countField) != list.size():
        throw IllegalStateException("countField 与 List 大小不一致")   // 选项 C
    for elem in list:
        bytes += elementCodec.serialize(elem)
```

### 4.3 游标推进的精确含义

每个元素 deserialize 完,消耗的 bit 数 = **它自己 serialize 出来的 bit 数**(二者对称)。外层 LIST 读取此数,推进游标。元素全定长 → 固定位数;元素含 lengthField/钩子 → 用 Phase 1 已有 `resolveSize` 算出。

---

## 5. 注册期校验(沿用 Phase 1 不变式纪律)

LIST 字段额外校验:

1. `countField` 必须引用真实、order 更小的字段(禁止前向引用)——复用 Phase 1 `validateReferences`
2. `elementClass` 必须是 `@ProtocolPacket` 实体
3. **元素必须自定边界**(2.2):elementClass 的字段集合,要么全定长(每个 `size>0`),要么靠自己的 `lengthField`/`countField` 定边界;**不能是「吃剩余字节」的变长实体**。检测规则:若 elementClass 的最后一个 `@ProtocolField` 字段既无 `size>0`、又无 `lengthField`、又非 `LIST`(LIST 自身靠 countField 定边界)→ 注册期抛异常

---

## 6. 向后兼容(硬指标)

| Phase 1 代码 | Phase 2a 后 |
|---|---|
| `Ipv4Header`(parity)、`MyProtocol`、所有 Phase 1 实体 | 零改动,全绿 |
| `@ProtocolField` 老属性 | 全保留;新增 2 个带默认值 |
| `FieldType` 老枚举值 | 保留,仅加 `LIST` |
| `ProtocolCodec` 公开方法(`serialize`/`deserialize`/`toPacket`/`fromPacket`) | 签名不变 |

新增属性全带默认值,Phase 1 实体一行不改照样编译、照样通过 parity 测试。

---

## 7. 验收标本:DNS Question 段(Qname,count 驱动变体)

DNS QName 真实结构:一串 label(每个 = 1字节长度 + 内容),最后以 0x00 结束。Phase 2a 不做结束标记,故用 **count 驱动变体**:显式 `labelCount` 字段给出 label 个数。

```java
@Data @ToString
@ProtocolPacket(port = 0)
public class DnsLabel {
    @ProtocolField(order = 1, size = 8) private int length;
    @ProtocolField(order = 2, type = FieldType.BYTES, lengthField = "length")
    private byte[] content;
}

@Data @ToString
@ProtocolPacket(port = 0)
public class DnsQuestion {
    @ProtocolField(order = 1, size = 8) private int labelCount;
    @ProtocolField(order = 2, type = FieldType.LIST,
                   countField = "labelCount", elementClass = DnsLabel.class)
    private java.util.List<DnsLabel> labels;
}
```

`DnsQuestion(labelCount=3, labels=[www,example,com])` serialize →
`03 77 77 77 05 65 78 61 6d 70 6c 65 03 63 6f 6d` → deserialize → 还原相同 List。

---

## 8. 测试与验收策略

| 测试 | 验证 |
|---|---|
| `DnsLabelTest` | 元素实体本身 round-trip(Phase 1 机制,顺带回归) |
| `DnsQuestionRoundTripTest` | count=3 → 标准字节 → 还原 List 相等(逐字节断言对照 RFC) |
| `CountSizeConsistencyTest` | countField=3 但 List=2 → 序列化抛异常(选项 C) |
| `ElementBoundaryValidationTest` | 元素无自定边界 → 注册期抛异常(选项 A) |
| **Phase 1 全量回归** | Ipv4ParityTest、MyProtocolRegression 等全绿 |

**验收边界(诚实说明)**:Phase 2a 不接真实 DNS 抓包(真实 DNS 用结束标记 0x00,非 count 驱动)。验收靠「逐字节对照 RFC 标准」的 round-trip,而非 pcap4j parity——因 pcap4j 1.8.2 不直接暴露 QName label 列表。比 Phase 1 弱一档,但 DNS 字节序是公开规范,等价于「RFC 当裁判」。

---

## 9. Phase 2a 交付清单

- [ ] `FieldType` 加 `LIST`
- [ ] `@ProtocolField` 加 `countField`/`elementClass`
- [ ] `ProtocolCodec`:LIST 分支(反序列化按 count 重复、序列化先校验一致性)
- [ ] 注册期校验:countField 引用合法性 + 元素自定边界
- [ ] `DnsLabel` / `DnsQuestion` 实体
- [ ] 4 类 LIST 测试 + Phase 1 全量回归
