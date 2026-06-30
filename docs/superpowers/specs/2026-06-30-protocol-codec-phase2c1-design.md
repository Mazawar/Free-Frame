# 通用协议编解码引擎 — Phase 2c1 设计(异质 TLV)

- 状态:草案(待用户复审)
- 日期:2026-06-30
- 试金石协议:DHCP Options(type→子结构分派,sentinel 终止)
- 范围:`type=LIST_TLV` + `dispatch` 分派表 + `tlvEndMarker` sentinel,标准 TLV(type+length 各1字节 + value)

---

## 1. 背景与目标

### 1.1 现状(Phase 1 + 2a + 2b + 2d + 2e 之后)

引擎已支持位字段、长度引用、嵌套、条件、字符串、count/sentinel/length 驱动的变长与集合、枚举、位标志。但**异质 TLV**(每个元素有 type,不同 type 对应不同子结构)不支持——这是最后一块"集合语义"短板。

Phase 2a 的 LIST 是**同质数组**(所有元素同一 elementClass);TLV 是**异质**(type 决定子结构),需运行时分派。

### 1.2 Phase 2c1 目标

支持**标准 TLV**:
- 元素 = type(1B) + length(1B) + value(length B)
- type → value 实体类的分派表(声明式 `dispatch`)
- sentinel 终止(type == endMarker 停,如 DHCP 0xFF)
- 未知 type 跳过(前向兼容)

做完能解析 DHCP Options、绝大多数标准 TLV 协议。

### 1.3 Phase 2c1 不做(留后续)

| 不含 | 留给 |
|---|---|
| 非标准元素结构(如 TCP Options 的 NOP 无 length、固定长度) | 后续 |
| 元素内字段级 sentinel(如 DNS 的 length=0 结束) | 后续 |
| 未知 type 零丢失(RawOption 占位) | 后续(现:跳过) |
| 校验和/CRC | Phase 3 |

**诚实边界**:Phase 2c1 是**标准 TLV**(type/length 各 1 字节,length = value 字节数不含自身)。TCP Options 那种 NOP(type=1,无 length,固定 1 字节)等非标准结构留后续。能解析 DHCP Options。

---

## 2. 关键设计抉择

### 2.1 分派表:注解字符串数组(路线 1 简化版)

```java
@ProtocolField(type=FieldType.LIST_TLV,
    tlvEndMarker=0xFF,
    dispatch={"1=SubnetMask", "3=Router", "53=DhcpMsgType"})
private List<Object> options;
```

- `dispatch` 用字符串数组 `"type=类名"`,引擎反射加载类
- 类名解析:`"SubnetMask"` 简单名时,引擎按「字段声明类所在包 + 简单名」解析(本项目的实体都在 `com.example.demo.protocol`);也支持全限定名 `"1=com.example.demo.protocol.SubnetMask"`。注册期校验:类必须存在且是 `@ProtocolPacket` 实体
- `List<Object>` 因为元素类型异质(子网掩码是 SubnetMask、路由是 Router)
- 比注解数组(`@Mapping(...)`)简洁;比接口实现(`TlvDispatcher`)更声明式

### 2.2 value 实体只含 value 部分(方式 A)

用户定义的 value 实体**只含 value 部分**,外壳(type/length)由引擎在 TLV 循环里统一读写:

```java
public class SubnetMask {
    @ProtocolField(order=1, size=32) private int mask;   // 只含 value:4 字节 IP
}
```

引擎读元素:读 type(1B) → 读 length(1B) → 按 type 分派 → 把接下来 length 字节喂给 value 实体的 codec。

### 2.3 未知 type 跳过(前向兼容)

dispatch 表没覆盖的 type:读 length,跳过 length 字节,继续。不中断、前向兼容。元素丢失(用户不知道有该 option);零丢失(RawOption)留后续。

### 2.4 sentinel 终止

`tlvEndMarker`(如 DHCP 0xFF):读到该 type 就结束。与 Phase 2b 的 sentinel 不同——TLV 的 sentinel 是「type 字段值」而非「独立字节」:引擎读 type,若 == endMarker 则停(且 endMarker 元素只有 type 字节,无 length/value)。

---

## 3. 注解 DSL 增量

### 3.1 新增

| 新增 | 默认 | 说明 |
|---|---|---|
| `FieldType.LIST_TLV` | (新枚举值) | 标记异质 TLV 字段 |
| `@ProtocolField.tlvEndMarker` | `-1` | sentinel:type == 此值就结束(0x00–0xFF) |
| `@ProtocolField.dispatch` | `{}` | String[],`"type=类名"` 映射 |

Phase 2c1 固定 type/length 各 1 字节(标准 TLV),**不加** `tlvTypeField`/`tlvLengthField`(外壳由引擎统一处理)。

### 3.2 注册期校验

LIST_TLV 字段额外校验:
1. `tlvEndMarker` 合法(0x00–0xFF 或 -1)
2. `dispatch` 每项格式 `"数字=类名"`,类名能反射加载 + 是 `@ProtocolPacket` 实体
3. `dispatch` 项的 type 值不重复

---

## 4. 编解码流程

### 4.1 反序列化(`readValue` 加 LIST_TLV 分支)

```
loop:
  peek type(下一字节)
  if 有 tlvEndMarker 且 type == tlvEndMarker: 消费标记字节, break
  if 无标记且到末尾: break
  type = readByte(); length = readByte()
  className = dispatch.get(type)
  if className == null: skip(length); continue       // 未知 type 跳过
  valueBytes = readBytes(length * 8)
  elem = codecFor(className).deserialize(valueBytes)
  list.add(elem)
```

### 4.2 序列化(`writeValue` 加 LIST_TLV 分支)

```
建反向 Map:类 → type(从 dispatch 构造)
for elem in list:
  type = reverseMap.get(elem.getClass())
  valueBytes = codecFor(elem.getClass()).serialize(elem)
  writeByte(type); writeByte(valueBytes.length); writeBytes(valueBytes)
if 有 tlvEndMarker: writeByte(tlvEndMarker)           // 追加 sentinel
```

### 4.3 resolveSize(序列化算总位数)

LIST_TLV 字段总位数 = 各元素(type 1B + length 1B + value)累加 + (有 endMarker 则 +8)。

---

## 5. 向后兼容(硬指标)

| Phase 1~2e 代码 | Phase 2c1 后 |
|---|---|
| 所有现有实体 | 零改动,全绿 |
| LIST_TLV 是新增能力 | 只有 `type=LIST_TLV` 字段才走新路径 |
| `@ProtocolField` 老属性 | 全保留;新增 2 个带默认值 |
| `FieldType` 老枚举值 | 保留,仅加 `LIST_TLV` |

**关键兼容点**:LIST_TLV 是全新分支,不碰现有 LIST/sentinel/count/enum/flag 路径。switch 表达式需加 `case LIST_TLV` 分支(否则编译失败,同 Phase 2a 加 LIST 时)。

---

## 6. 验收标本:DHCP Options

```java
// value 实体(只含 value 部分)
@Data @ProtocolPacket(port=0)
public class SubnetMask {
    @ProtocolField(order=1, size=32) private int mask;   // 192.168.1.1
}
@Data @ProtocolPacket(port=0)
public class Router {
    @ProtocolField(order=1, size=32) private int address;
}
@Data @ProtocolPacket(port=0)
public class DhcpMsgType {
    @ProtocolField(order=1, size=8) private int type;    // 1 字节
}

// 含 TLV 字段的实体
@Data @ProtocolPacket(port=0)
public class DhcpOptions {
    @ProtocolField(order=1, type=FieldType.LIST_TLV,
        tlvEndMarker=0xFF,
        dispatch={"1=SubnetMask", "3=Router", "53=DhcpMsgType"})
    private List<Object> options = new ArrayList<>();
}
```

字节布局(标准 TLV):
```
01 04 C0 A8 01 01    type=1(SubnetMask) len=4 value=192.168.1.1
03 04 C0 A8 01 FE    type=3(Router)     len=4 value=192.168.1.254
35 01 02             type=53(MsgType)   len=1 value=2(OFFER)
FF                   type=255(End) → 终止
```

---

## 7. 测试与验收策略

| 测试 | 验证 |
|---|---|
| `TlvBasicTest` | 已知 type round-trip:3 个 DHCP option → 标准字节 → 还原(类型正确) |
| `TlvUnknownTypeTest` | 未知 type 跳过:type=99 跳过其 length,前后元素不受影响 |
| `TlvSentinelTest` | sentinel 终止:0xFF 处停;无标记读到末尾 |
| `TlvValidationTest` | dispatch 格式错/类名不存在/type 重复 → 注册期报错 |
| **Phase 1~2e 全量回归** | 47 个测试全绿 |

**验收边界**:Phase 2c1 是标准 TLV(type/length 各1字节)。TCP Options(NOP 无 length 等)非标准结构留后续。

---

## 8. Phase 2c1 交付清单

- [ ] `FieldType.LIST_TLV` 枚举值
- [ ] `@ProtocolField.tlvEndMarker` / `dispatch` 属性
- [ ] `FieldInfo` 读新属性 + 注册期校验(dispatch 解析 + 反向 Map)
- [ ] `ProtocolCodec`:LIST_TLV 分支(反序列化 peek-read-skip、序列化反向查表+sentinel、resolveSize)
- [ ] `SubnetMask`/`Router`/`DhcpMsgType`/`DhcpOptions` 实体
- [ ] 4 类测试 + Phase 1~2e 回归
