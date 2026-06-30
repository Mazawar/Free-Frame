# 通用协议编解码引擎 — Phase 1 设计

- 状态:草案(待用户复审)
- 日期:2026-06-30
- 试金石协议:IPv4 头
- 范围:结构完整(位字段 + 长度引用 + 变长字段 + 字符串 + 协议嵌套 + 条件字段)

---

## 1. 背景与目标

### 1.1 现状

`ProtocolCodec` 当前只能解析「固定长度 + 字节对齐整数 + 末尾单个变长 payload」的自定义协议。对照常见标准协议的 8 类结构特性,全部不支持:

1. 位字段(子字节,如 IPv4 Version/IHL 各 4 bit)
2. 长度引用(某字段长度 = 另一字段值)
3. 协议嵌套(实体引用实体)
4. 重复/变长字段(TLV / Options 集合)
5. 条件字段(依据另一字段值决定是否出现)
6. 校验和 / CRC
7. 枚举 / 标志位语义
8. 字符串编码

### 1.2 终局目标

**用「实体类 + 注解」定义任意协议,开箱即用、像 Wireshark 一样抓包解析,最终能代替 pcap4j 原生协议的解析能力。**

诚实边界:有两类本质上是过程性的行为,纯 POJO 无法声明式表达——
- TCP 流重组 / IP 分片重组(状态机)
- 流式分帧(下一帧边界依赖前一帧)

这两类由 Phase 3 的钩子机制(任意 Java 逻辑)处理,不伪装成纯声明。本设计严格遵守「声明式优先 + 类型安全钩子逃生舱」的哲学。

### 1.3 Phase 1 范围(本文档只覆盖)

| 特性 | Phase 1 | 后续 |
|---|---|---|
| ① 位字段 | ✅ | — |
| ② 长度引用 | ✅(单一变长字段) | — |
| ③ 协议嵌套(NESTED) | ✅ | — |
| ④ 重复/变长集合(TLV/list) | ❌ | Phase 2 |
| ⑤ 条件字段(presentIf 相等) | ✅ | Phase 2 扩充复杂条件 |
| ⑥ 校验和/CRC 钩子 | ❌ | Phase 3 |
| ⑦ 枚举/标志位语义 | ❌ | Phase 2 |
| ⑧ 字符串编码 | ✅ | — |

剪裁依据:Phase 1 覆盖「所有能被静态结构描述」的协议(IPv4 / Modbus / DNS 头等)。集合语义(TLV)与校验和各自有独立的 DSL 设计议题,单独成 spec,不与结构 DSL 耦合。

---

## 2. DSL 哲学:声明式优先 + 钩子逃生舱(路线 3)

80% 常见情况用**声明式字段引用**(只引用字段名,不写表达式);20% 复杂情况(算术、多字段联动)用**类型安全的钩子接口**。

纪律:
- 声明式只能**引用字段的原始值**,不能写 `totalLen-20` 这类算术。
- 算术 / 多字段联动一律走钩子(`DynamicSize`)。
- 两者可共存于同一实体:简单字段声明式,个别复杂字段钩子。

---

## 3. 核心模型

### 3.1 位游标(BitCursor)

用「位偏移」替代当前的「字节偏移」,使子字节字段可表达。

- 反序列化:cursor 从 `offset*8` 起,每读一个 size 位字段,cursor += size。
- 序列化:cursor 从 0 起,每写一个字段,cursor += size。
- **位打包规则**(定死):
  - 字节内 MSB 优先(IPv4 Version 占 byte0 高 4 位、IHL 占低 4 位)。
  - 跨字节大端(网络序)。
  - 允许字段跨越字节边界(12-bit 字段可横跨 byte0 低 4 位 + byte1 全 8 位)。

**向后兼容发现**:现有 `@ProtocolField.size` 实际已按 bit 语义(`headerSize = sum(size)/8`,且校验 `sum%8==0`)。Phase 1 不改名,仅**取消「必须 8 的倍数」限制**,`size=4` 即可表达 4-bit 字段。`MyProtocol` 的 `size=8/16/32` 零改动。

### 3.2 FieldContext(只读视图)

反/序列化过程中「已解析字段」的快照,动态行为的唯一数据来源。

```java
public interface FieldContext {
    int getInt(String fieldName);          // 常见用途:长度引用、条件判断
    Object get(String fieldName);          // 原始对象值(字符串/字节/嵌套实体)
    boolean hasRead(String fieldName);     // 是否已解析(防前向引用)
    Object entity();                       // 实体对象本身(多字段联动用)
}
```

**两条不变式(注册时强制校验,违反抛异常):**
1. `lengthField` / `presentIf` 引用的字段,必须 `order` 更小(禁止前向引用)。
2. 引用的字段名必须真实存在。

填充节奏:字段值「解析完才入 ctx」,引用者永远只能看到先于自己解析完的字段。

---

## 4. 注解 DSL 完整定义

### 4.1 `@ProtocolField`(字段级)

| 属性 | 类型 | 说明 | 新增? |
|---|---|---|---|
| `order` | int | 字段排列顺序(必填) | 沿用 |
| `size` | int | 位数(取消「8 的倍数」限制) | 语义升级 |
| `type` | FieldType | 值类型,默认按 Java 类型推断 | 新增 |
| `lengthField` | String | 变长字段长度引用某字段名 | 新增 |
| `lengthUnit` | LengthUnit | `lengthField` 单位:`BYTES`/`BITS`,默认 `BYTES`(`COUNT` 留 Phase 2,见 §4.3) | 新增 |
| `presentIf` | String | 条件字段:`"field==值"` 才出现 | 新增 |
| `charset` | String | STRING 类型字符集,默认 `UTF-8` | 新增 |

### 4.2 `FieldType` 枚举

| 类型 | Java 字段 | 说明 |
|---|---|---|
| `INT`(默认) | byte/short/int/long | 带符号,按 Java 类型 |
| `UNSIGNED` | int/long | 无符号(size≤63) |
| `BYTES` | byte[] | 原始字节 |
| `STRING` | String | 文本,配 charset |
| `NESTED` | 实体类 | 协议嵌套,递归编解码 |

### 4.3 长度引用语义(`lengthField` + `lengthUnit`)

Phase 1 仅支持两种单位:

| `lengthUnit` | 含义 | 典型协议 | Java 字段 |
|---|---|---|---|
| `BYTES`(默认) | 长度字段值 = 字节数 | IP totalLen、Modbus length | byte[]/String |
| `BITS` | = 位数 | 某些位域协议 | byte[] |

`COUNT`(元素个数,如 DNS label 数 / TCP options 数)涉及集合语义,整体留 Phase 2。

Phase 1 约束:**一个实体至多一个 `lengthField` 变长字段**。更复杂情况(算术、多字段联动)走钩子(`DynamicSize`)。

### 4.4 钩子接口(逃生舱)

```java
public interface DynamicSize {
    /** 计算字段位长度;返回 -1 表示交还声明式(lengthField/size)。 */
    long computeSize(String fieldName, FieldContext ctx);
}
```

实体可选实现。判定优先级(每字段,所有路径最终统一换算成 **bit**):

1. 实体实现 DynamicSize 且 `computeSize` 返回 >=0 → 用钩子值(**已是 bit**,不换算)
2. 否则 `lengthField` 非空 → `ctx.getInt(lengthField) * 系数`,系数:`BYTES`→×8、`BITS`→×1
3. 否则 → 用 `size`(**已是 bit**)

`resolveSize` 返回值恒为 bit,反序列化按 bit 推进游标,序列化按 bit 写入。

---

## 5. 编解码流程

### 5.1 反序列化 `deserialize(bytes, offset, length)`

```
obj = newEntity(); ctx = 新建; cursor = offset*8
for field in 按 order 排序:
    if field.presentIf 非空 且 ctx.eval(presentIf)==false: continue
    size = resolveSize(field, ctx): 钩子 > lengthField > size
    value = bitRead(bytes, cursor, size)        // MSB / 大端
    obj.set(field, convert(value, type))        // INT/UNSIGNED/BYTES/STRING/NESTED
    ctx.put(field.name, value)
    cursor += size
return obj
```

### 5.2 序列化 `serialize(obj)`(对称)

ctx 一次性装满所有字段值 → 同样 resolveSize → 逐字段位写。

### 5.3 NESTED

递归调用被引用实体类的 codec,把子实体字节嵌入/截取。

---

## 6. 向后兼容(硬指标)

| 老代码 | Phase 1 后 |
|---|---|
| `MyProtocol`(size=8/16/32,@Payload) | 不改一行,照样 round-trip |
| `size` 语义 | 仍是 bit,取消「8 的倍数」限制 |
| `@Payload` | 保留,等价于「实体最后一个变长字段」 |
| `ProtocolCodec` 公开方法 | 签名不变(deserialize/serialize/toPacket/fromPacket) |

`MyProtocol` 纳入回归测试。

---

## 7. 验收标本:IPv4 头

```
偏移 字段          长度    特性
0    Version       4 bit   位字段
0    IHL           4 bit   位字段(被钩子引用)
1    DSCP          6 bit   位字段
1    ECN           2 bit   位字段
2    Total Length  16 bit
4    Identification 16 bit
6    Flags         3 bit   位字段
6    Fragment Offset 13 bit 位字段
8    TTL           8 bit
9    Protocol      8 bit
10   Header Checksum 16 bit (Phase1 普通字段;Phase3 校验和)
12   Source IP      32 bit
16   Destination IP 32 bit
20   Options        变长    DynamicSize 钩子:(IHL-5)*4 字节
```

```java
@Data @ToString
@ProtocolPacket(port = 0)
public class Ipv4Header implements DynamicSize {
    @ProtocolField(order=1,  size=4)   private int version;
    @ProtocolField(order=2,  size=4)   private int ihl;
    @ProtocolField(order=3,  size=6)   private int dscp;
    @ProtocolField(order=4,  size=2)   private int ecn;
    @ProtocolField(order=5,  size=16)  private int totalLength;
    @ProtocolField(order=6,  size=16)  private int identification;
    @ProtocolField(order=7,  size=3)   private int flags;
    @ProtocolField(order=8,  size=13)  private int fragmentOffset;
    @ProtocolField(order=9,  size=8)   private int ttl;
    @ProtocolField(order=10, size=8)   private int protocol;
    @ProtocolField(order=11, size=16)  private int headerChecksum;
    @ProtocolField(order=12, size=32)  private int sourceIp;
    @ProtocolField(order=13, size=32)  private int destinationIp;
    @ProtocolField(order=14, type=BYTES) private byte[] options;

    @Override public long computeSize(String field, FieldContext ctx) {
        if ("options".equals(field)) return (ctx.getInt("ihl")*4L - 20) * 8; // bit
        return -1;
    }
}
```

IPv4 头本身无嵌套字段,故另用 `EthernetFrame`(含 `@ProtocolField(type=NESTED) Ipv4Header payload`)单独验证嵌套特性,两个特性各自干净验收。

---

## 8. 测试与验收策略

**核心原则:不信任自己的解析器,信任 pcap4j 的——用 parity 对比验收。**

### 8.1 确定性单测(进 CI,可复现)—— vs pcap4j parity

- 提交真实 `.pcap` 样本 `src/test/resources/ipv4-sample.pcap`
- 读出每个 IP 包的原始 IP 头字节 + pcap4j 解析的字段值(裁判答案)
- 喂给 `Ipv4Header` codec → 逐字段断言全部与 pcap4j 相等
- 覆盖 `ihl>5`(带 options)验证钩子
- `MyProtocol` round-trip 回归(零改动承诺)

parity 对比的价值:能抓出「序列化端与解析端犯同一错」的自欺风险(纯 round-trip 抓不到)。

### 8.2 Web UI 实时演示

- 现有抓包流程加只读分支:抓到的 IP 包**同时**用 `Ipv4Header` codec 解析
- 页面展示每个字段解析结果(version/ihl/ttl/源·目的 IP …)
- 不改原有 UDP 分发架构,只增只读分支
- 启动后访问真实流量,眼见为实

### 8.3 单元覆盖

- 位字段:`size=4/6/13/3` 单字节/跨字节读写
- 长度引用:`lengthField` 三种 `lengthUnit`
- 条件字段:`presentIf` 两取值的字节差异
- 校验期:前向引用 / 引用不存在字段 → 注册抛异常

---

## 9. Phase 1 交付清单

- [ ] `BitCursor` 位游标读写(MSB / 大端 / 跨字节)
- [ ] `FieldContext` 只读视图 + 注册期不变式校验
- [ ] `FieldType` / `LengthUnit` 枚举
- [ ] `@ProtocolField` 扩展(type/lengthField/lengthUnit/presentIf/charset,size 取消限制)
- [ ] `DynamicSize` 钩子接口 + 优先级解析
- [ ] `ProtocolCodec` 重构(位游标 + ctx + NESTED 递归)
- [ ] `Ipv4Header` / `EthernetFrame` 实体定义
- [ ] `.pcap` parity 单测 + `MyProtocol` 回归
- [ ] Web UI 只读解析分支
