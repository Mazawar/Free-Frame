# 通用协议编解码引擎 — Phase 2c2 设计(元素内 sentinel)

- 状态:草案(待用户复审)
- 日期:2026-06-30
- 试金石协议:真实 DNS QName(length=0 表示结束)
- 范围:`sentinelOn`/`sentinelValue`,LIST 的第三种终止方式——peek 元素首字段值,==sentinelValue 则停

---

## 1. 背景与目标

### 1.1 现状(Phase 1~3a 之后)

引擎已支持 LIST 的两种终止方式:count 驱动(Phase 2a)、字节级 sentinel(Phase 2b)。但**元素内 sentinel**(DNS QName 的 `length=0 表示结束`)不支持——这是 Phase 2b 留的诚实边界。

Phase 2b 的字节级 sentinel 检查"下一个**独立字节**是否为标记";DNS 的 `0x00` 是 **label 的 length 字段的值**(元素内),不是独立标记字节。本质不同。

### 1.2 Phase 2c2 目标

支持元素内 sentinel:LIST 字段声明 `sentinelOn`(元素里哪个字段判定)+ `sentinelValue`(==此值则终止)。引擎反序列化时 peek 元素首字段值,==sentinelValue 则停(消费该字段)。

做完能解析**真实 DNS QName**(label 序列 + 0x00 结束),填补 Phase 2b 留的缺口。

### 1.3 Phase 2c2 不做(留后续)

| 不含 | 留给 |
|---|---|
| DNS 指针压缩(RFC 1035 §4.1.4 的 0xC0 压缩指针) | 后续 |
| 非标准 TLV 元素结构(TCP Options 的 NOP) | 后续 |

**诚实边界**:Phase 2c2 只做"元素首字段值判定终止"。真实 DNS QName 的主体(label 序列)能解析;指针压缩(0xC0)是另一套机制,留后续。

---

## 2. 关键设计抉择

### 2.1 sentinelOn/sentinelValue(路线 1)

`@ProtocolField(type=LIST, elementClass=..., sentinelOn="length", sentinelValue=0)`:引擎 peek 元素 sentinelOn 字段的 size 位,==sentinelValue 则停。声明式,与 countField/sentinel(2b)并列。

### 2.2 peek 机制

引擎反序列化时,在读取每个元素前 peek 游标当前位置的 sentinelFieldSize 位(sentinelOn 字段的 size,从 elementCodec 查);==sentinelValue 则消费 sentinelFieldSize 位 + break;否则正常反序列化元素(那个字段会被元素自己读掉)。

### 2.3 与 Phase 2a/2b 并列(第三种终止)

| 终止方式 | Phase | 判定 |
|---|---|---|
| count 驱动 | 2a | 读 N 个 |
| 字节级 sentinel | 2b | peekByte == sentinel(独立字节) |
| **元素内 sentinel** | **2c2** | peek 元素首字段值 == sentinelValue |

注册期校验:三种互斥。

---

## 3. 注解 DSL 增量

| 新增 | 默认 | 说明 |
|---|---|---|
| `@ProtocolField.sentinelOn` | `""` | 元素里终止判定字段名 |
| `@ProtocolField.sentinelValue` | `0` | 该字段==此值则终止 |

**无新 FieldType、无新枚举值。** 复用 `type=LIST`。

### 3.1 注册期校验

LIST 字段若声明 `sentinelOn`:
1. 与 `countField`/`sentinel`(2b)**互斥**
2. `sentinelOn` 必须是 elementClass 的真实字段(查 elementCodec)
3. `sentinelOn` 字段的 size 已知(用于 peek 多少位)
4. elementClass 仍须满足 Phase 2a 的"自定边界"约束

---

## 4. 编解码流程

### 4.1 反序列化(LIST + sentinelOn 子分支)

```
sentinelFieldSize = elementCodec 查 sentinelOn 字段的 size(注册期已校验存在)
loop:
  peek 游标当前位置的 sentinelFieldSize 位
  if 值 == sentinelValue: 消费 sentinelFieldSize 位, break
  elem = elementCodec.deserialize(从游标起)
  list.add(elem); 推进游标
```

> 实现注记:`sentinelFieldSize` 在注册期校验时从 elementClass 的 FieldInfo 查得(sentinelOn 字段的 size),缓存进当前 FieldInfo,反序列化时直接用。需给 elementCodec/FieldInfo 暴露"按字段名查 size"的能力(或注册期解析时存好)。

### 4.2 序列化(LIST + sentinelOn 子分支)

```
for elem in list: serialize(elem)
写 sentinelValue 到 sentinelFieldSize 位(末尾追加结束标记)
```

---

## 5. 向后兼容(硬指标)

| Phase 1~3a 代码 | Phase 2c2 后 |
|---|---|
| 所有现有实体(DnsQuestion count、DnsNameSentinel 2b、DhcpOptions TLV 等) | 零改动,全绿 |
| sentinelOn 是新增终止方式 | 只有 `type=LIST` + `sentinelOn` 才走新路径 |
| `@ProtocolField` 老属性 | 全保留;新增 2 个带默认值 |
| `FieldType` 老枚举值 | 不变 |

---

## 6. 验收标本:真实 DNS QName

```java
// 元素(同 Phase 2a)
@Data @ProtocolPacket(port = 0)
public class DnsLabel {
    @ProtocolField(order = 1, size = 8) private int length;
    @ProtocolField(order = 2, type = FieldType.BYTES, lengthField = "length")
    private byte[] content;
}

// 顶层:真实 DNS QName(length=0 表示结束)
@Data @ProtocolPacket(port = 0)
public class DnsName {
    @ProtocolField(order = 1, type = FieldType.LIST,
            elementClass = DnsLabel.class,
            sentinelOn = "length", sentinelValue = 0)
    private List<DnsLabel> labels;
}
```

字节布局(真实 DNS):
```
03 77 77 77      length=3, "www"
05 65 78 61 6d 70 6c 65   length=5, "example"
03 63 6f 6d      length=3, "com"
00               ← length=0 → 终止(消费这 1 字节)
```

---

## 7. 测试与验收策略

| 测试 | 验收 |
|---|---|
| `DnsNameElementSentinelTest` | round-trip:`[www,example,com]` → 标准字节 → 还原 labels |
| `DnsNameSentinelEdgeTest` | 空 QName(仅 0x00)→ 空 labels;无 0x00 → 读到末尾 |
| `SentinelOnValidationTest` | sentinelOn 与 countField/sentinel 互斥→报错;sentinelOn 字段不存在→报错 |
| **Phase 1~3a 全量回归** | 57 个测试全绿 |

**验收**:逐字节对照 RFC 1035(不做 pcap4j parity,因 pcap4j DNS 解析含指针压缩,复杂)。真实 DNS QName 主体(label 序列)能 round-trip。

---

## 8. Phase 2c2 交付清单

- [ ] `@ProtocolField.sentinelOn`/`sentinelValue` 属性
- [ ] `FieldInfo` 读新属性 + 注册期校验(互斥、字段存在)
- [ ] `ProtocolCodec`:LIST 的 sentinelOn 子分支(反序列化 peek-终止、序列化追加)
- [ ] `DnsName` 实体(复用 DnsLabel)
- [ ] 3 类测试 + Phase 1~3a 回归
