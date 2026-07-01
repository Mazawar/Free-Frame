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

### Phase 2d(本版本新增)

- **枚举语义** —— 字段类型用 `ProtocolEnum`(实现该接口的 enum),配 `enumClass` 指定具体枚举:协议里的语义数字(IP protocol 17=UDP)自动映射,可读、类型安全。未知值不中断,存原始数字(`UnknownEnumValue`),序列化零丢失。

示例:

```java
public enum IpProtocol implements ProtocolEnum {
    ICMP(1), TCP(6), UDP(17);
    private final int v;
    IpProtocol(int v) { this.v = v; }
    public int value() { return v; }
}

// 字段声明为 ProtocolEnum 接口类型 + enumClass 指定具体枚举
@ProtocolField(order=9, size=8, enumClass=IpProtocol.class)
private ProtocolEnum protocol;   // 读到 17 → IpProtocol.UDP;读到 89(未知)→ UnknownEnumValue(89)
```

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

### Phase 2c1(本版本新增)

- **异质 TLV** —— 标准 TLV(type+length 各1字节 + value)按 type 分派到不同 value 实体,sentinel 终止,未知 type 跳过。`dispatch={"1=SubnetMask","3=Router"}` 声明分派表。

示例:

```java
@ProtocolField(type=FieldType.LIST_TLV, tlvEndMarker=0xFF,
    dispatch={"1=SubnetMask", "3=Router", "53=DhcpMsgType"})
private List<Object> options;   // type=1→SubnetMask, type=3→Router, type=0xFF→End
```

### Phase 3(本版本新增)

- **校验和钩子** —— 实体实现 `Checksum` 接口 + `@ChecksumField` 标记,序列化时引擎自动置0→算→回写。试金石:IPv4 头校验和(16位反码求和),parity 对照 pcap4j(整头字节一致)。

示例:

```java
public class Ipv4HeaderWithChecksum implements Checksum {
    @ProtocolField(order=10, size=16) @ChecksumField
    private int headerChecksum;

    public long compute(String field, byte[] serialized) {
        return onesComplementSum(serialized);  // serialized 里校验和字段已置 0
    }
}
```

**TCP/UDP 伪首部校验和(Phase 3a)**:TCP 段的校验和覆盖伪首部(源IP/目的IP/协议来自外层 IP 包)。实体用 transient 字段存伪首部信息,`compute` 拼伪首部 + serialized 反码求和。parity 对照 pcap4j 通过。

```java
public class TcpSegmentWithChecksum implements Checksum {
    // ... TCP 字段 ...
    private transient int pseudoSourceIp;   // 用户装配时填(来自外层 IP)
    private transient int pseudoDestIp;
    private transient int pseudoProtocol;   // TCP=6

    public long compute(String field, byte[] serialized) {
        byte[] pseudo = buildPseudoHeader(serialized.length);
        return onesComplementSum(concat(pseudo, serialized));
    }
}
```

### 仍未覆盖(后续)

- UDP 校验和实体(同 TCP 机制)
- CRC16(Modbus 等)
- 校验和反序列化端验证(结果存实体)
- 非标准 TLV 元素结构(如 TCP Options 的 NOP 无 length、固定长度)
- 元素内字段级 sentinel(如 DNS 的「label 长度=0 表示结束」)
- 未知 TLV type 零丢失(RawOption 占位)
- 复杂条件(位掩码 / `&&`)
- 流重组 / 分片重组(过程性,留钩子)

### 设计文档

- 设计 spec:
  - Phase 1:`docs/superpowers/specs/2026-06-30-protocol-codec-phase1-design.md`
  - Phase 2a:`docs/superpowers/specs/2026-06-30-protocol-codec-phase2a-design.md`
  - Phase 2b:`docs/superpowers/specs/2026-06-30-protocol-codec-phase2b-design.md`
  - Phase 2d:`docs/superpowers/specs/2026-06-30-protocol-codec-phase2d-design.md`
  - Phase 2e:`docs/superpowers/specs/2026-06-30-protocol-codec-phase2e-design.md`
  - Phase 2c1:`docs/superpowers/specs/2026-06-30-protocol-codec-phase2c1-design.md`
  - Phase 3:`docs/superpowers/specs/2026-06-30-protocol-codec-phase3-design.md`
  - Phase 3a:`docs/superpowers/specs/2026-06-30-protocol-codec-phase3a-design.md`
- 实施计划:
  - Phase 1:`docs/superpowers/plans/2026-06-30-protocol-codec-phase1.md`
  - Phase 2a:`docs/superpowers/plans/2026-06-30-protocol-codec-phase2a.md`
  - Phase 2b:`docs/superpowers/plans/2026-06-30-protocol-codec-phase2b.md`
  - Phase 2d:`docs/superpowers/plans/2026-06-30-protocol-codec-phase2d.md`
  - Phase 2e:`docs/superpowers/plans/2026-06-30-protocol-codec-phase2e.md`
  - Phase 2c1:`docs/superpowers/plans/2026-06-30-protocol-codec-phase2c1.md`
  - Phase 3:`docs/superpowers/plans/2026-06-30-protocol-codec-phase3.md`
  - Phase 3a:`docs/superpowers/plans/2026-06-30-protocol-codec-phase3a.md`
