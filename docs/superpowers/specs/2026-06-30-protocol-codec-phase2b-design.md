# 通用协议编解码引擎 — Phase 2b 设计(length 驱动 + sentinel 驱动)

- 状态:草案(待用户复审)
- 日期:2026-06-30
- 试金石协议:IP payload(length 驱动)、C 字符串(sentinel blob)、sentinel-LIST(重复实体)
- 范围:`@ProtocolField.lengthAdjust`(length 偏移)+ `@ProtocolField.sentinel`(结束标记字节)

---

## 1. 背景与目标

### 1.1 现状(Phase 1 + 2a 之后)

已支持:位字段、length 引用(`lengthField`)、嵌套、条件、字符串、count 驱动同质数组(`type=LIST` + `countField`)。但「集合/变长字段怎么结束」还缺两种驱动:

- **length 驱动**:某字段值 = 后续总字节数,但常见协议有固定开销(IP 的 `totalLen-20`、TCP 的 `-20`)。Phase 1 的 `lengthField` 只能纯引用,不支持偏移。
- **sentinel(结束标记)驱动**:读到某固定字节值(如 `0x00`)就结束。C 字符串、DHCP Options(0xFF)等大量协议用此机制。

### 1.2 Phase 2b 目标

补齐这两种结束驱动:
1. `lengthAdjust` —— 让 `lengthField` 支持「值 = lengthField值 + 偏移」(解决 IP totalLen-20 这类)
2. `sentinel` —— 字节级结束标记驱动,支持 BYTES(blob 读到标记)和 LIST(逐元素读到标记)

### 1.3 Phase 2b 不做(留后续)

| 不含 | 留给 |
|---|---|
| 元素内字段级 sentinel(如 DNS 的「label 长度=0 表示结束」) | Phase 2c |
| 异质 TLV(type→子结构分派) | Phase 2c |
| 复杂条件(位掩码/&&) | 后续 |
| 校验和/CRC | Phase 3 |

**诚实边界**:Phase 2b 的 sentinel 是**字节级**——引擎在元素/字节之间检查「下一个字节是不是标记值」。真实 DNS QName 的「0x00 = 长度为0的label」属元素内判定(标记藏元素结构里),留 Phase 2c。Phase 2b 能解析 C 字符串、DHCP Options、length 驱动数组,覆盖面已很大。

---

## 2. 关键设计抉择

### 2.1 length 偏移:`lengthAdjust`(声明式,选项 A)

`lengthField` 加一个整数偏移属性 `lengthAdjust`(默认 0):
```
字段长度(字节) = lengthField值 + lengthAdjust
```
例:`@ProtocolField(lengthField="totalLen", lengthAdjust=-20)` → payload 占 `totalLen-20` 字节。

理由:`某长度字段 - 固定开销`是极常见模式(IP/TCP/Modbus 都有),声明式比钩子简洁太多。复杂算术仍走 `DynamicSize` 钩子。`lengthAdjust=0` 时 Phase 1 的 `lengthField` 行为零变化(关键兼容点)。

### 2.2 sentinel:字节级 `sentinel=0xNN`(路线 2)

`@ProtocolField` 加 `sentinel`(默认 -1 表示不用):
```java
@ProtocolField(type=BYTES, sentinel=0x00)   // 读到字节 0x00 就停
```
- BYTES 字段:逐字节读到标记,消费标记字节,返回之前的字节
- LIST 字段:逐元素读,元素之间 peek 下一个字节,命中标记就停

判定粒度:**字节级**(标记是独立字节,不属于任何元素)。元素内字段级 sentinel(DNS 的 length=0)留 Phase 2c。

### 2.3 sentinel 复用 `type=LIST`,与 countField 互斥(路线 A)

sentinel 和 count 本质都是「LIST,终止方式不同」。统一在 `type=LIST` 下:
- `countField`(2a):数到 N 停
- `sentinel`(2b):碰到标记停

二者**互斥**(同时给报错)。元素机制(elementClass、remainingFromCursor、逐元素反序列化)完全复用 Phase 2a,零重造。对 BYTES 字段(非 LIST),sentinel 单独适用。

### 2.4 sentinel 标记字节:消费即丢弃(不存字段)

结束标记是结构性的,用户通常不关心其值(固定那个数)。Phase 2b 不存。需存储将来加 `sentinelField`。

---

## 3. 注解 DSL 增量

### 3.1 `@ProtocolField` 新增属性(均带默认值)

| 属性 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `lengthAdjust` | int | `0` | length 驱动偏移:`字段字节长度 = lengthField值 + lengthAdjust` |
| `sentinel` | int | `-1` | sentinel 字节值(0x00–0xFF);-1 表示不用 |

**无新枚举值。** sentinel 复用 `type=LIST`/`BYTES`。

### 3.2 判定优先级(每字段)

```
sentinel >= 0       → sentinel 终止(逐字节/逐元素读到标记停)
countField 非空      → count 驱动(Phase 2a)
lengthField 非空     → length 驱动(值 = lengthField值 + lengthAdjust)
否则                 → 固定 size
```

### 3.3 注册期校验(三种终止互斥)

1. `sentinel` 与 `countField` **互斥**(同时给报错)
2. `sentinel` 与 `lengthField` **互斥**(三种终止至多用一种)
3. `sentinel` 值合法范围 `0x00–0xFF`(给 -1 之外的负数或 >255 报错)

---

## 4. BitCursor 增量

| 方法 | 用途 |
|---|---|
| `peekByte()` | sentinel 反序列化:偷看当前字节(不推进游标),判断是否结束标记 |

(Phase 2a 的 `remainingFromCursor`/`skipBits` 继续复用。)

---

## 5. 编解码流程

### 5.1 反序列化(`readValue` 增量)

BYTES/LIST 字段若 `sentinel>=0` → sentinel 分支:
```
sentinel 终止:
  if BYTES:
      逐字节读到 == sentinel;消费标记字节;返回之前的字节
      (列表可能直接以标记开头 = 空内容)
  if LIST:
      loop {
          peek 下一个字节
          if 命中 sentinel → 消费标记字节 + break
          else → elem = elementCodec.deserialize(从游标起);list.add(elem);推进游标
      }
      (列表可能直接以标记开头 = 空列表,返回 size 0)
```

注:peek 在「读取任何元素之前」也执行一次,故空列表/空内容合法(首字节即标记)。

length 驱动(`lengthField`+`lengthAdjust`):复用 Phase 1 `resolveSize` 的 lengthField 分支,值改为 `lengthField值 + lengthAdjust`(字节)*8(bit)。

### 5.2 序列化(`writeValue`/`resolveSize` 增量)

- sentinel 字段:写完数据后追加标记字节。`resolveSize`(序列化算总位数)= 数据位数 + 8(标记)
- length 驱动:`resolveSize` 用 `lengthField值 + lengthAdjust` 算

---

## 6. 向后兼容(硬指标)

| Phase 1/2a 代码 | Phase 2b 后 |
|---|---|
| Ipv4Header、MyProtocol、DnsQuestion(count)、所有现有实体 | 零改动,全绿 |
| `@ProtocolField` 老属性 | 全保留;新增 2 个带默认值 |
| `lengthField`(Phase 1) | 仍工作;`lengthAdjust=0` 时行为完全不变(值 = lengthField + 0) |
| `FieldType` 老枚举值 | 不变(Phase 2b 不加枚举值) |
| `ProtocolCodec` 公开方法 | 签名不变 |

**关键兼容点**:`lengthAdjust=0` 让 Phase 1 的 `lengthField` 行为零变化。

---

## 7. 验收标本

### 7.1 length 驱动 —— IP payload

```java
@ProtocolPacket
public class IpFragment {
    @ProtocolField(order=1, size=16) private int totalLen;
    @ProtocolField(order=2, type=BYTES, lengthField="totalLen", lengthAdjust=-20)
    private byte[] payload;   // 占 totalLen - 20 字节
}
```
`totalLen=24, payload=4字节` → 序列化后 payload 正好 4 字节。

### 7.2 sentinel —— C 字符串(blob)

```java
@ProtocolPacket
public class CStringPacket {
    @ProtocolField(order=1, type=BYTES, sentinel=0x00)
    private byte[] text;   // 读到 0x00 就停(标记消费丢弃)
}
```
`text="Hi"` → `48 69 00` → 反序列化还原 `Hi`(不含 0x00)。

### 7.3 sentinel —— LIST(重复实体)

复用 Phase 2a 的 `DnsLabel`,顶层用 sentinel 而非 count:3 个 label + 0x00 → 反序列化得 3 元素。

---

## 8. 测试与验收策略

| 测试 | 验证 |
|---|---|
| `LengthAdjustTest` | `IpFragment` round-trip:totalLen=24→payload 4 字节 |
| `SentinelBytesTest` | `CStringPacket` round-trip:`Hi` → `48 69 00` → 还原 `Hi` |
| `SentinelListTest` | LIST+sentinel:3 个 DnsLabel + 0x00 → 还原 3 元素 |
| `SentinelValidationTest` | sentinel 与 countField/lengthField 互斥→报错;sentinel 越界→报错 |
| **Phase 1+2a 全量回归** | Ipv4Parity、MyProtocol、DnsQuestion(count)等全绿 |

**验收边界**:Phase 2b 不接真实 DNS 抓包(DNS 的 0x00 是元素内判定,留 Phase 2c)。验收靠逐字节对照规范。

---

## 9. Phase 2b 交付清单

- [ ] `@ProtocolField` 加 `lengthAdjust`/`sentinel`
- [ ] `BitCursor` 加 `peekByte`
- [ ] `ProtocolCodec`:sentinel 分支(反序列化 peek-read、序列化追加标记)+ lengthAdjust 应用到 lengthField 解析
- [ ] 注册期校验:互斥 + 范围
- [ ] `IpFragment`/`CStringPacket`/sentinel-LIST 实体
- [ ] 4 类测试 + Phase 1+2a 回归
