# 通用协议编解码引擎 — Phase 3a 设计(TCP/UDP 伪首部校验和)

- 状态:草案(待用户复审)
- 日期:2026-06-30
- 试金石协议:TCP 段校验和(含伪首部)
- 范围:纯实体侧——`TcpSegmentWithChecksum`(transient 伪首部字段 + compute 拼伪首部),引擎零改动

---

## 1. 背景与目标

### 1.1 现状(Phase 3 之后)

Phase 3 实现了校验和钩子框架(`Checksum` 接口 + `@ChecksumField` + serialize 置0→算→回写),试金石是 IPv4 头校验和(16位反码求和,覆盖单层头)。但 **TCP/UDP 校验和**未支持——它覆盖**伪首部**,而伪首部的源IP/目的IP/协议来自**外层 IP 包**,不在 TCP/UDP 实体本身里(跨层依赖)。

### 1.2 Phase 3a 目标

让 TCP/UDP 实体的校验和能算对(含伪首部),parity 对照 pcap4j。

### 1.3 Phase 3a 不做(留后续)

| 不含 | 留给 |
|---|---|
| UDP 校验和实体(同机制,TCP 做完照搬) | 后续(机制相同) |
| CRC16(Modbus) | 后续 |
| 校验和反序列化验证 | 后续 |

**诚实边界**:Phase 3a 只做 TCP 段校验和(伪首部 + 反码求和)。UDP 同机制(TODO)。引擎零改动。

---

## 2. 关键设计抉择

### 2.1 伪首部信息:实体 transient 字段(路线 1)

TCP 校验和的伪首部需要源IP/目的IP/协议(来自外层 IP 包)。三条路:
- 路线 1:实体加 transient 字段存伪首部信息,用户装配时填 ✅ **选**
- 路线 2:扩展 Checksum 接口传上下文对象,引擎嵌套透传(改动大、耦合嵌套)
- 路线 3:用户自己拼伪首部字节(负担全推用户)

选路线 1:最简单,引擎零改动。伪首部信息本质是"这个 TCP 包要装进哪个 IP 包"——装配参数,用户构造实体时本来就知道。

### 2.2 引擎零改动(关键结论)

Phase 3 的 `Checksum.compute(field, serialized)` 签名完全够用:
- `serialized` = TCP 段字节(校验和字段已置0)
- transient 字段在对象里,compute 能读到
- 用户在 compute 里拼伪首部(12B)+ serialized,反码求和

伪首部末尾的"TCP 长度"= `serialized.length`,compute 自己能算,不用用户填。

**引擎一个字都不改。** Phase 3a 纯实体侧工作。这是 Phase 3 分层设计的回报:校验和算法(含伪首部)是钩子的事,引擎只管"何时算、放哪"。

### 2.3 transient 字段:不加 @ProtocolField 即不序列化

引擎按 `@ProtocolField` 注解扫描字段——没注解的字段引擎不碰。所以 transient 字段连 `transient` 关键字都不严格需要,但建议加(防将来引入 Java 序列化混淆)。

---

## 3. 实体写法(TCP 段)

```java
@Data @ProtocolPacket(port = 0)
public class TcpSegmentWithChecksum implements Checksum {
    @ProtocolField(order = 1, size = 16) private int srcPort;
    @ProtocolField(order = 2, size = 16) private int dstPort;
    @ProtocolField(order = 3, size = 32) private long seqNumber;
    @ProtocolField(order = 4, size = 32) private long ackNumber;
    @ProtocolField(order = 5, size = 4)  private int dataOffset;
    @ProtocolField(order = 6, size = 3)  private int reserved;
    @ProtocolField(order = 7, size = 9)  private int flags;
    @ProtocolField(order = 8, size = 16) private int window;
    @ProtocolField(order = 9, size = 16) @ChecksumField private int checksum;
    @ProtocolField(order = 10, size = 16) private int urgentPointer;

    // 伪首部信息(transient,不序列化,用户装配时填)
    private transient int pseudoSourceIp;
    private transient int pseudoDestIp;
    private transient int pseudoProtocol;   // TCP=6

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"checksum".equals(field)) return -1;
        byte[] pseudo = buildPseudoHeader(serialized.length);
        byte[] full = concat(pseudo, serialized);
        return onesComplementSum(full);
    }

    private byte[] buildPseudoHeader(int tcpLength) {
        // 12 字节:源IP(4) + 目IP(4) + 0(1) + 协议(1) + TCP长度(2)
        ...
    }
    // onesComplementSum 同 Phase 3 IPv4 实现
}
```

---

## 4. 向后兼容(硬指标)

| Phase 1~3 代码 | Phase 3a 后 |
|---|---|
| 所有现有实体、Ipv4HeaderWithChecksum | 零改动,全绿 |
| Phase 3a 纯新增实体 | 引擎零改动,不碰任何现有路径 |

**关键**:引擎零改动。Phase 3a 只是新增一个实体 + 一个测试。

---

## 5. 测试与验收

| 测试 | 验证 |
|---|---|
| `TcpChecksumParityTest` | **硬验收**:我们的 TCP 校验和(含伪首部)== pcap4j 的 TCP 校验和 |
| **Phase 1~3 全量回归** | 56 个测试全绿 |

**验收**:用 pcap4j 构造 Ethernet→IP→TCP 包(correctChecksumAtBuild=true),取 TCP 段字节 + 我们用同样字段 + 填伪首部序列化 → 我们的 checksum == pcap4j 的。

---

## 6. Phase 3a 交付清单

- [ ] `TcpSegmentWithChecksum` 实体(transient 伪首部字段 + compute 拼伪首部)
- [ ] `TcpChecksumParityTest`(对照 pcap4j)
- [ ] Phase 1~3 回归
