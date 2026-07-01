# 通用协议编解码引擎 Phase 3a — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 TCP 段校验和能算对(含伪首部),parity 对照 pcap4j。

**Architecture:** **引擎零改动**——Phase 3 的 `Checksum` 接口 + `@ChecksumField` + serialize 第三步完全够用。新增一个 `TcpSegmentWithChecksum` 实体(transient 伪首部字段 + compute 拼伪首部 + 反码求和)+ 一个 parity 测试。伪首部信息(源IP/目的IP/协议)存在 transient 字段,用户装配时填。

**Tech Stack:** Java 25,Spring Boot 4.1,JUnit Jupiter 6 + AssertJ 3.27,Lombok,pcap4j 1.8.2(裁判)。

**参考 spec:** `docs/superpowers/specs/2026-06-30-protocol-codec-phase3a-design.md`

**测试约定:** `./mvnw test -Dtest=XxxTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`(单类);全量 `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`。Git Bash on Windows。

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `protocol/TcpSegmentWithChecksum.java` | TCP 段实体(transient 伪首部字段 + compute 拼伪首部 + 反码求和) | 新建 |
| `test/.../TcpChecksumParityTest.java` | 硬验收:TCP 校验和 parity 对照 pcap4j | 新建 |

引擎零改动。所有测试为纯 JUnit。

---

## Task 1: TcpSegmentWithChecksum 实体 + parity 测试

**Files:**
- Create: `src/main/java/com/example/demo/protocol/TcpSegmentWithChecksum.java`
- Test: `src/test/java/com/example/demo/protocol/TcpChecksumParityTest.java`

- [ ] **Step 1: 创建 TcpSegmentWithChecksum 实体**

`src/main/java/com/example/demo/protocol/TcpSegmentWithChecksum.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ChecksumField;
import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.Checksum;
import lombok.Data;
import lombok.ToString;

import java.io.ByteArrayOutputStream;

/**
 * TCP 段(带校验和钩子,含伪首部)。checksum 字段序列化时由引擎置0→算→回写。
 * 伪首部(源IP/目的IP/协议)存在 transient 字段,用户装配时填。
 * 算法:伪首部(12B) + serialized(TCP头) 反码求和取反。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class TcpSegmentWithChecksum implements Checksum {

    @ProtocolField(order = 1, size = 16) private int srcPort;
    @ProtocolField(order = 2, size = 16) private int dstPort;
    @ProtocolField(order = 3, size = 32) private long seqNumber;
    @ProtocolField(order = 4, size = 32) private long ackNumber;
    @ProtocolField(order = 5, size = 4)  private int dataOffset;   // 4 bit
    @ProtocolField(order = 6, size = 6)  private int reserved;      // 6 bit
    @ProtocolField(order = 7, size = 6)  private int flags;         // 6 bit (URG/ACK/PSH/RST/SYN/FIN)
    @ProtocolField(order = 8, size = 16) private int window;
    @ProtocolField(order = 9, size = 16)
    @ChecksumField
    private int checksum;
    @ProtocolField(order = 10, size = 16) private int urgentPointer;

    // 伪首部信息(transient,不序列化,用户装配时填)
    private transient int pseudoSourceIp;
    private transient int pseudoDestIp;
    private transient int pseudoProtocol;   // TCP=6

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"checksum".equals(field)) {
            return -1;  // 不接管
        }
        byte[] pseudo = buildPseudoHeader(serialized.length);
        byte[] full = concat(pseudo, serialized);
        return onesComplementSum(full);
    }

    /** 拼伪首部 12 字节:源IP(4) + 目IP(4) + 0(1) + 协议(1) + TCP长度(2)。 */
    private byte[] buildPseudoHeader(int tcpLength) {
        byte[] p = new byte[12];
        p[0] = (byte) (pseudoSourceIp >>> 24);
        p[1] = (byte) (pseudoSourceIp >>> 16);
        p[2] = (byte) (pseudoSourceIp >>> 8);
        p[3] = (byte) pseudoSourceIp;
        p[4] = (byte) (pseudoDestIp >>> 24);
        p[5] = (byte) (pseudoDestIp >>> 16);
        p[6] = (byte) (pseudoDestIp >>> 8);
        p[7] = (byte) pseudoDestIp;
        p[8] = 0;                       // 保留零
        p[9] = (byte) pseudoProtocol;   // 协议(TCP=6)
        p[10] = (byte) (tcpLength >>> 8);
        p[11] = (byte) tcpLength;
        return p;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(a.length + b.length);
        bos.writeBytes(a);
        bos.writeBytes(b);
        return bos.toByteArray();
    }

    /** 16 位反码求和(同 Phase 3 IPv4 实现)。 */
    private static long onesComplementSum(byte[] data) {
        long sum = 0;
        for (int i = 0; i + 1 < data.length; i += 2) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
        }
        if ((data.length & 1) != 0) {
            sum += (data[data.length - 1] & 0xFF) << 8;
        }
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (~sum) & 0xFFFF;
    }
}
```

> 注:byte 12 的位布局 `dataOffset(4) + reserved(6) + flags(6) = 16 bit`,与 pcap4j 一致。

- [ ] **Step 2: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 写 parity 测试**

`src/test/java/com/example/demo/protocol/TcpChecksumParityTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class TcpChecksumParityTest {

    @Test
    void ourTcpChecksumMatchesPcap4j() throws Exception {
        java.net.Inet4Address src = (java.net.Inet4Address) InetAddress.getByName("10.0.0.1");
        java.net.Inet4Address dst = (java.net.Inet4Address) InetAddress.getByName("10.0.0.2");

        // pcap4j 构造 TCP 段(correctChecksumAtBuild=true,需显式设 srcAddr/dstAddr 给 TCP builder)
        TcpPacket.Builder tcpB = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) 12345))
                .dstPort(TcpPort.getInstance((short) 80))
                .sequenceNumber(1000)
                .acknowledgmentNumber(0)
                .dataOffset((byte) 5)        // 5 × 32bit 字 = 20 字节(无 options)
                .reserved((byte) 0)
                .psh(false).ack(false).urg(false).rst(false).syn(true).fin(false)  // SYN
                .window((short) 8192)
                .urgentPointer((short) 0)
                .correctLengthAtBuild(true)
                .correctChecksumAtBuild(true)
                .srcAddr(src)                 // ← 必须显式设(伪首部用)
                .dstAddr(dst);                // ← 必须显式设
        // 包进 IP(IP 的 correctChecksumAtBuild 不影响 TCP,这里只为构造完整包)
        IpV4Packet.Builder ipB = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr(src)
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(tcpB);
        IpV4Packet ipPkt = ipB.build();
        TcpPacket tcpPkt = (TcpPacket) ipPkt.getPayload();

        short pcapChecksum = tcpPkt.getHeader().getChecksum();
        byte[] pcapTcpBytes = tcpPkt.getRawData();   // TCP 段(头+空payload),checksum 在 offset 16-17

        // 我们的 codec 序列化同样的字段
        ProtocolCodec<TcpSegmentWithChecksum> codec = new ProtocolCodec<>(TcpSegmentWithChecksum.class);
        TcpSegmentWithChecksum ours = new TcpSegmentWithChecksum();
        ours.setSrcPort(12345);
        ours.setDstPort(80);
        ours.setSeqNumber(1000);
        ours.setAckNumber(0);
        ours.setDataOffset(5);
        ours.setReserved(0);
        // SYN=0x02:pcap4j 的 flags 位序 URG/ACK/PSH/RST/SYN/FIN → SYN 是 bit1 → 0x02
        ours.setFlags(0x02);
        ours.setWindow(8192);
        ours.setUrgentPointer(0);
        ours.setChecksum(0);   // 引擎会算
        // 伪首部信息(与 pcap4j 的 srcAddr/dstAddr/protocol 一致)
        ours.setPseudoSourceIp(0x0A000001);      // 10.0.0.1
        ours.setPseudoDestIp(0x0A000002);        // 10.0.0.2
        ours.setPseudoProtocol(6);               // TCP
        byte[] ourBytes = codec.serialize(ours);

        // parity:我们的校验和(offset 16-17)== pcap4j 的
        int ourChecksum = ((ourBytes[16] & 0xFF) << 8) | (ourBytes[17] & 0xFF);
        assertThat(ourChecksum).isEqualTo(pcapChecksum & 0xFFFF);

        // 额外:整个 TCP 段字节应一致(我们的字节 16-17 是算出来的,应等于 pcap4j 的)
        assertThat(ourBytes).containsExactly(pcapTcpBytes);
    }
}
```

> **pcap4j flags 位序**(验证):byte 12-13 的低 6 位,URG(bit5)/ACK(bit4)/PSH(bit3)/RST(bit2)/SYN(bit1)/FIN(bit0)。SYN=0x02。我们的 `flags` 字段 6 位,同序。

- [ ] **Step 4: 运行确认通过**

Run: `./mvnw test -Dtest=TcpChecksumParityTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 1, Failures: 0`

> 这是硬验收:我们的整个 TCP 段字节(含算出的校验和)与 pcap4j 完全一致。若校验和算错,网络会丢包。

- [ ] **Step 5: 全量回归**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 56 + 新 1 = 57)。引擎零改动,Phase 1~3 不受影响。

- [ ] **Step 6: 提交**

```bash
git add src/main/java/com/example/demo/protocol/TcpSegmentWithChecksum.java src/test/java/com/example/demo/protocol/TcpChecksumParityTest.java
git commit -m "feat(protocol): TcpSegmentWithChecksum with pseudo-header checksum parity"
```

---

## Task 2: 全量验证 + 文档更新

- [ ] **Step 1: 全量测试**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(57)

- [ ] **Step 2: 全量编译打包**

Run: `./mvnw package 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 更新 README**

在 `README.md` 的「### Phase 3」节里,把伪首部从未覆盖移到已覆盖。找到「### 仍未覆盖(后续)」里的「TCP/UDP 校验和(含伪首部、跨层依赖)」,删掉它,并在 Phase 3 节补充一句 TCP 伪首部已支持。

- [ ] **Step 4: 提交**

```bash
git add README.md
git commit -m "docs: Phase 3a TCP pseudo-header checksum"
```

---

## 完成标志

全部 Task 完成后:
- [ ] `./mvnw test` 全绿(57 个测试)
- [ ] `./mvnw package` 成功
- [ ] **硬验收**:TCP 校验和 parity == pcap4j(整段字节一致)
- [ ] Phase 1~3 全量回归不破
