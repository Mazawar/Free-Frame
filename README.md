# Free-Frame

通用协议编解码引擎:用「实体类 + 注解」定义任意二进制协议,开箱即用、像 Wireshark 一样抓包解析。

## Protocol Codec (Phase 1)

定义一个协议 = 写一个实体类。引擎根据 `@ProtocolField` / `@Payload` 注解自动完成实体 ⇄ 字节序列的双向映射。

### 支持的特性

- **位级字段** —— 子字节(4/6/13 bit 等),MSB 优先 / 网络序大端 / 跨字节边界
- **声明式长度引用** —— `lengthField` 引用某字段值作为变长长度(BYTES / BITS 单位)
- **条件字段** —— `presentIf = "field==value"` 满足才出现
- **协议嵌套** —— `type = NESTED`,实体引用实体,递归编解码
- **字符串编码** —— `charset`(UTF-8 / ASCII / GBK …)
- **算术复杂长度** —— 实现 `DynamicSize` 钩子(如 IPv4 的 `(IHL-5)*4`)
- **类型** —— `INT` / `UNSIGNED` / `BYTES` / `STRING` / `NESTED`

### 验收

- **真实 IPv4 包与 pcap4j 逐字段 parity** —— `Ipv4ParityTest`:用 pcap4j 构造标准 IPv4 包,喂给我们的 `Ipv4Header` codec,13 个字段(version/ihl/tos/totalLength/identification/flags/fragmentOffset/ttl/protocol/headerChecksum/sourceIp/destinationIp/options)全部与 pcap4j 一致。证明「实体类定义」匹配久经考验的解析器。
- `MyProtocol` 老协议零改动回归
- 位字段 / 嵌套 / 条件 / 长度引用 / 钩子 / 注册期不变式 单元覆盖(23 个测试全绿)

### 运行

```bash
./mvnw spring-boot:run
# 打开 http://localhost:8080
# 选网卡 → 开始抓包,IPv4 流量会显示 [IPv4] v=4 ihl=5 ttl=64 proto=17 src=.. dst=..
```

测试:`./mvnw test`

### 示例

定义一个协议(实体类):

```java
@Data @ToString
@ProtocolPacket(port = 0)
public class Ipv4Header implements DynamicSize {
    @ProtocolField(order=1,  size=4)   private int version;
    @ProtocolField(order=2,  size=4)   private int ihl;        // 32-bit words
    @ProtocolField(order=3,  size=8)   private int tos;
    @ProtocolField(order=4,  size=16)  private int totalLength;
    @ProtocolField(order=5,  size=16)  private int identification;
    @ProtocolField(order=6,  size=3)   private int flags;      // reserved/df/mf
    @ProtocolField(order=7,  size=13)  private int fragmentOffset;
    @ProtocolField(order=8,  size=8)   private int ttl;
    @ProtocolField(order=9,  size=8)   private int protocol;
    @ProtocolField(order=10, size=16)  private int headerChecksum;
    @ProtocolField(order=11, size=32)  private int sourceIp;
    @ProtocolField(order=12, size=32)  private int destinationIp;
    @ProtocolField(order=13, type=BYTES) private byte[] options;

    @Override public long computeSize(String field, FieldContext ctx) {
        if ("options".equals(field)) return (ctx.getInt("ihl") * 4L - 20) * 8; // bit
        return -1;
    }
}
```

序列化 / 反序列化:

```java
ProtocolCodec<Ipv4Header> codec = new ProtocolCodec<>(Ipv4Header.class);
byte[] bytes = codec.serialize(header);     // 实体 → 字节
Ipv4Header parsed = codec.deserialize(bytes); // 字节 → 实体
```

### Phase 2a(本版本新增)

- **count 驱动的同质重复数组** —— `type=LIST` + `countField` + `elementClass`,`List<X>` 字段,元素是另一个实体类(如 DNS label)。元素必须自定边界(注册期校验);序列化时要求 `countField == list.size()`。

示例(DNS Question 段,count 驱动变体):

```java
@ProtocolPacket
public class DnsLabel {
    @ProtocolField(order=1, size=8) private int length;
    @ProtocolField(order=2, type=BYTES, lengthField="length") private byte[] content;
}

@ProtocolPacket
public class DnsQuestion {
    @ProtocolField(order=1, size=8) private int labelCount;
    @ProtocolField(order=2, type=LIST, countField="labelCount", elementClass=DnsLabel.class)
    private List<DnsLabel> labels;
}
```

### Phase 2b(本版本新增)

- **length 偏移** —— `lengthAdjust`:字段字节长度 = `lengthField值 + lengthAdjust`(解决 IP totalLen-20 这类)
- **sentinel 结束标记** —— `sentinel=0xNN`:读到该字节就停。支持 BYTES(blob)和 LIST(重复实体),与 countField/lengthField 互斥

示例:

```java
// IP payload:占 totalLen - 20 字节
@ProtocolField(type=BYTES, lengthField="totalLen", lengthAdjust=-20) private byte[] payload;

// C 字符串:读到 0x00 结束
@ProtocolField(type=BYTES, sentinel=0x00) private byte[] text;
```

### 仍未覆盖(后续 Phase)

- 元素内字段级 sentinel(如 DNS 的「label 长度=0 表示结束」)
- 异质 TLV(type → 子结构分派,如 TCP/DHCP Options)
- 复杂条件(位掩码 / `&&`)
- 校验和 / CRC 钩子(IPv4/TCP/UDP 校验和、伪首部)
- 流重组 / 分片重组(过程性,留钩子)

### 设计文档

- 设计 spec:
  - Phase 1:`docs/superpowers/specs/2026-06-30-protocol-codec-phase1-design.md`
  - Phase 2a:`docs/superpowers/specs/2026-06-30-protocol-codec-phase2a-design.md`
  - Phase 2b:`docs/superpowers/specs/2026-06-30-protocol-codec-phase2b-design.md`
- 实施计划:
  - Phase 1:`docs/superpowers/plans/2026-06-30-protocol-codec-phase1.md`
  - Phase 2a:`docs/superpowers/plans/2026-06-30-protocol-codec-phase2a.md`
  - Phase 2b:`docs/superpowers/plans/2026-06-30-protocol-codec-phase2b.md`
