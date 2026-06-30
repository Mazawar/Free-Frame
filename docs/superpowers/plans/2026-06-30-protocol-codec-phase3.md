# 通用协议编解码引擎 Phase 3 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给引擎加上校验和钩子——实体实现 `Checksum` 接口 + `@ChecksumField` 标记,序列化时引擎自动置0→算→回写。试金石:IPv4 头校验和 parity 对照 pcap4j。

**Architecture:** 新增 `Checksum` 接口(`long compute(field, serializedBytes)`)和 `@ChecksumField` 注解(字段级,无属性)。序列化改动集中在 `serialize` 的写字段循环:遇 @ChecksumField → 强制写 0 + 记字节偏移;循环后新增"compute + 回写"第三步。反序列化零改动(C2:不验证)。**无新 FieldType、无 @ProtocolField 改动**——校验和字段是普通 INT 字段 + 标记注解,Phase 3 纯增量。

**Tech Stack:** Java 25,Spring Boot 4.1,JUnit Jupiter 6 + AssertJ 3.27,Lombok。

**参考 spec:** `docs/superpowers/specs/2026-06-30-protocol-codec-phase3-design.md`

**测试约定:** `./mvnw test -Dtest=XxxTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`(单类);全量 `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`。Git Bash on Windows。

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `core/Checksum.java` | 校验和钩子接口(`long compute(field, serializedBytes)`) | 新建 |
| `annotation/ChecksumField.java` | 字段级注解,标记校验和字段(无属性) | 新建 |
| `core/ProtocolCodec.java` | FieldInfo 读 @ChecksumField + serialize 第三步(置0→算→回写) | 修改 |
| `protocol/Ipv4HeaderWithChecksum.java` | 试金石实体(实现 Checksum + 反码求和) | 新建 |
| `test/.../ChecksumAlgorithmTest.java` | 反码求和算法正确性 | 新建 |
| `test/.../Ipv4ChecksumParityTest.java` | 硬验收:校验和 vs pcap4j | 新建 |
| `test/.../ChecksumRoundTripTest.java` | 校验和 round-trip | 新建 |

包路径 `com.example.demo.protocol.*`。所有测试为纯 JUnit。

---

## Task 1: Checksum 接口 + @ChecksumField 注解

**Files:**
- Create: `src/main/java/com/example/demo/protocol/core/Checksum.java`
- Create: `src/main/java/com/example/demo/protocol/annotation/ChecksumField.java`

- [ ] **Step 1: 创建 Checksum 接口**

`src/main/java/com/example/demo/protocol/core/Checksum.java`:
```java
package com.example.demo.protocol.core;

/** 校验和钩子:实体可选实现,提供校验和计算逻辑。 */
public interface Checksum {

    /**
     * 计算校验和字段的值。
     *
     * @param fieldName  哪个字段要算校验和(@ChecksumField 标记的字段名)
     * @param serialized 整个实体序列化后的字节(校验和字段已被引擎置 0)
     * @return 校验和值;返回 -1 表示不接管该字段(走普通路径)
     */
    long compute(String fieldName, byte[] serialized);
}
```

- [ ] **Step 2: 创建 @ChecksumField 注解**

`src/main/java/com/example/demo/protocol/annotation/ChecksumField.java`:
```java
package com.example.demo.protocol.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标记校验和字段。序列化时引擎在该位置置 0 → 调 compute → 回写。实体须实现 Checksum。 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ChecksumField {
}
```

- [ ] **Step 3: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 4: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/Checksum.java src/main/java/com/example/demo/protocol/annotation/ChecksumField.java
git commit -m "feat(codec): add Checksum hook interface and @ChecksumField annotation"
```

---

## Task 2: ProtocolCodec serialize 第三步(置0→算→回写,核心)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`

这是 Phase 3 核心。三处改动:FieldInfo 读 @ChecksumField;serialize 写字段循环遇校验和字段强制写0+记偏移;循环后新增第三步 compute+回写。

- [ ] **Step 1: FieldInfo 加 checksumField 标志**

在 `ProtocolCodec.java` 的 `FieldInfo` 内部类,加 `final boolean checksumField;`。
- 在 `FieldInfo(Field f)` 构造器里加:`this.checksumField = f.isAnnotationPresent(com.example.demo.protocol.annotation.ChecksumField.class);`
- 在私有 `FieldInfo(Field f, String name)`(@Payload)构造器里加:`this.checksumField = false;`

- [ ] **Step 2: serialize 写字段循环 + 第三步**

找到 `serialize` 方法里的写字段循环(当前是):
```java
            BitCursor cursor = new BitCursor((totalBits + 7) / 8);
            for (FieldInfo fi : fixedFields) {
                if (!evalPresentIf(fi.presentIf, ctx)) {
                    continue;
                }
                long size = resolveSize(fi, obj, ctx, false, 0);
                writeValue(fi, obj, cursor, (int) size, ctx);
            }
            if (payloadField != null && payloadData != null) {
                cursor.writeBytes(payloadData);
            }
            return cursor.bytes();
```

替换为(校验和字段:记偏移 + 写0;循环后第三步 compute+回写):
```java
            BitCursor cursor = new BitCursor((totalBits + 7) / 8);
            // 记录校验和字段的偏移(field → 起始字节偏移),供第三步回写
            java.util.Map<String, Integer> checksumOffsets = new java.util.HashMap<>();
            for (FieldInfo fi : fixedFields) {
                if (!evalPresentIf(fi.presentIf, ctx)) {
                    continue;
                }
                long size = resolveSize(fi, obj, ctx, false, 0);
                if (fi.checksumField) {
                    // 校验和字段:记录起始字节偏移,强制写 0
                    int startByte = cursor.bitOffset() / 8;
                    checksumOffsets.put(fi.name, startByte);
                    cursor.writeBits(0L, (int) size);
                } else {
                    writeValue(fi, obj, cursor, (int) size, ctx);
                }
            }
            if (payloadField != null && payloadData != null) {
                cursor.writeBytes(payloadData);
            }
            // 第三步:若实体实现 Checksum,对每个校验和字段 compute → 回写
            if (obj instanceof Checksum cs) {
                byte[] bytes = cursor.bytes();
                for (FieldInfo fi : fixedFields) {
                    if (!fi.checksumField) continue;
                    long computed = cs.compute(fi.name, bytes);
                    if (computed < 0) continue;  // 钩子不接管
                    int size = (int) resolveSize(fi, obj, ctx, false, 0);
                    int truncated = (int) (computed & (size >= 64 ? -1L : ((1L << size) - 1)));
                    int startByte = checksumOffsets.get(fi.name);
                    writeBitsAtOffset(bytes, startByte, size, truncated);
                }
                return bytes;
            }
            return cursor.bytes();
```

并新增私有静态方法 `writeBitsAtOffset`(在类中,写指定字节偏移/位数的值,用于回写校验和):
```java
    /** 把 value 的低 size 位写进 bytes 从 startByte 字节起的 MSB 优先位置(供校验和回写)。 */
    private static void writeBitsAtOffset(byte[] bytes, int startByte, int size, long value) {
        for (int i = 0; i < size; i++) {
            int absBit = startByte * 8 + i;
            int byteIdx = absBit / 8;
            int bitInByte = 7 - (absBit % 8);
            long bit = (value >> (size - 1 - i)) & 1L;
            if (bit == 1) {
                bytes[byteIdx] |= (byte) (1 << bitInByte);
            } else {
                bytes[byteIdx] &= (byte) ~(1 << bitInByte);
            }
        }
    }
```

> 注:`writeBitsAtOffset` 复用 BitCursor 的 MSB 优先位序逻辑,但直接操作字节数组(回写已序列化的 buffer)。`truncated` 把 compute 结果截断到字段位数(如 16 位)。

- [ ] **Step 3: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 4: 全量回归(确认 Phase 1~2c1 未破,普通实体不受影响)**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(53)。普通实体不实现 Checksum,走原路径;Ipv4Header 等 parity 测试照常。

- [ ] **Step 5: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java
git commit -m "feat(codec): serialize checksum fields (zero-fill, compute, rewrite)"
```

---

## Task 3: Ipv4HeaderWithChecksum 实体 + 算法测试

**Files:**
- Create: `src/main/java/com/example/demo/protocol/Ipv4HeaderWithChecksum.java`
- Test: `src/test/java/com/example/demo/protocol/ChecksumAlgorithmTest.java`

- [ ] **Step 1: 创建 Ipv4HeaderWithChecksum**

`src/main/java/com/example/demo/protocol/Ipv4HeaderWithChecksum.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ChecksumField;
import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.Checksum;
import lombok.Data;
import lombok.ToString;

/**
 * IPv4 头(带校验和钩子)。headerChecksum 字段序列化时由引擎置0→算→回写。
 * 反码求和算法由本实体实现(compute)。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class Ipv4HeaderWithChecksum implements Checksum {

    @ProtocolField(order = 1, size = 4)   private int version;
    @ProtocolField(order = 2, size = 4)   private int ihl;
    @ProtocolField(order = 3, size = 8)   private int tos;
    @ProtocolField(order = 4, size = 16)  private int totalLength;
    @ProtocolField(order = 5, size = 16)  private int identification;
    @ProtocolField(order = 6, size = 3)   private int flags;
    @ProtocolField(order = 7, size = 13)  private int fragmentOffset;
    @ProtocolField(order = 8, size = 8)   private int ttl;
    @ProtocolField(order = 9, size = 8)   private int protocol;
    @ProtocolField(order = 10, size = 16)
    @ChecksumField
    private int headerChecksum;
    @ProtocolField(order = 11, size = 32) private int sourceIp;
    @ProtocolField(order = 12, size = 32) private int destinationIp;

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"headerChecksum".equals(field)) {
            return -1;  // 不接管
        }
        return onesComplementSum(serialized);
    }

    /** IPv4 16 位反码求和。serialized 里校验和字段已被引擎置 0。 */
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

- [ ] **Step 2: 写算法正确性测试**

`src/test/java/com/example/demo/protocol/ChecksumAlgorithmTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ChecksumAlgorithmTest {

    /**
     * 用一个最简 IPv4 头(20字节)验证:序列化后校验和字段被引擎填上正确值。
     * 全 0 输入(除 version/ihl)→ 校验和 = 反码求和(version/ihl 字节 = 0x45)。
     */
    @Test
    void checksumFieldIsComputedOnSerialize() {
        ProtocolCodec<Ipv4HeaderWithChecksum> codec = new ProtocolCodec<>(Ipv4HeaderWithChecksum.class);

        Ipv4HeaderWithChecksum h = new Ipv4HeaderWithChecksum();
        h.setVersion(4);
        h.setIhl(5);
        h.setTos(0);
        h.setTotalLength(20);
        h.setIdentification(0);
        h.setFlags(0);
        h.setFragmentOffset(0);
        h.setTtl(0);
        h.setProtocol(0);
        h.setHeaderChecksum(0);   // 占位,引擎会重算
        h.setSourceIp(0);
        h.setDestinationIp(0);

        byte[] out = codec.serialize(h);
        // 校验和字段在字节偏移 10-11(IPv4 头第 11-12 字节,0-indexed 10-11)
        int computed = ((out[10] & 0xFF) << 8) | (out[11] & 0xFF);
        // 手算:全头除校验和外只有 0x45 00 00 14(其余0),反码求和
        // 0x4500 + 0x0014 = 0x4514;取反 = 0xBAEB
        assertThat(computed).isEqualTo(0xBAEB);
    }
}
```

> 注:0x4500(version4/ihl5/tos0) + 0x0014(totalLen20) = 0x4514;~0x4514 & 0xFFFF = 0xBAEB。这是手算的期望值,验证算法+回写都对。

- [ ] **Step 3: 运行确认通过**

Run: `./mvnw test -Dtest=ChecksumAlgorithmTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 1, Failures: 0`

- [ ] **Step 4: 提交**

```bash
git add src/main/java/com/example/demo/protocol/Ipv4HeaderWithChecksum.java src/test/java/com/example/demo/protocol/ChecksumAlgorithmTest.java
git commit -m "feat(protocol): Ipv4HeaderWithChecksum with ones-complement checksum"
```

---

## Task 4: IPv4 校验和 parity 验收(对照 pcap4j)

**Files:**
- Test: `src/test/java/com/example/demo/protocol/Ipv4ChecksumParityTest.java`

- [ ] **Step 1: 写 parity 测试**

`src/test/java/com/example/demo/protocol/Ipv4ChecksumParityTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class Ipv4ChecksumParityTest {

    @Test
    void ourChecksumMatchesPcap4j() throws Exception {
        // pcap4j 构造 IP 包(correctChecksumAtBuild=true,自动算校验和)
        IpV4Packet pcapPkt = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .totalLength((short) 20)
                .identification((short) 0)
                .reservedFlag(false)
                .dontFragmentFlag(false)
                .moreFragmentFlag(false)
                .fragmentOffset((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.1"))
                .dstAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.2"))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .build();

        short pcapChecksum = pcapPkt.getHeader().getHeaderChecksum();
        byte[] pcapHeaderBytes = pcapPkt.getHeader().getRawData();

        // 我们的 codec 序列化同样的字段
        ProtocolCodec<Ipv4HeaderWithChecksum> codec = new ProtocolCodec<>(Ipv4HeaderWithChecksum.class);
        Ipv4HeaderWithChecksum ours = new Ipv4HeaderWithChecksum();
        ours.setVersion(4);
        ours.setIhl(5);
        ours.setTos(0);
        ours.setTotalLength(20);
        ours.setIdentification(0);
        ours.setFlags(0);   // pcap4j: all flags false
        ours.setFragmentOffset(0);
        ours.setTtl(64);
        ours.setProtocol(17);   // UDP
        ours.setHeaderChecksum(0);  // 引擎会算
        ours.setSourceIp(0x0A000001);      // 10.0.0.1
        ours.setDestinationIp(0x0A000002); // 10.0.0.2
        byte[] ourBytes = codec.serialize(ours);

        // parity:我们的校验和字段(offset 10-11)== pcap4j 的校验和
        int ourChecksum = ((ourBytes[10] & 0xFF) << 8) | (ourBytes[11] & 0xFF);
        assertThat(ourChecksum).isEqualTo(pcapChecksum & 0xFFFF);

        // 额外:除校验和外,整个头字节应一致(我们的字节 10-11 是算出来的,应等于 pcap4j 的)
        assertThat(ourBytes).containsExactly(pcapHeaderBytes);
    }
}
```

- [ ] **Step 2: 运行确认通过**

Run: `./mvnw test -Dtest=Ipv4ChecksumParityTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 1, Failures: 0`

> 这是最强验收:我们的整头字节(含算出的校验和)与 pcap4j 完全一致。若校验和算错,网络会丢包。

- [ ] **Step 3: 提交**

```bash
git add src/test/java/com/example/demo/protocol/Ipv4ChecksumParityTest.java
git commit -m "test(protocol): IPv4 checksum parity vs pcap4j"
```

---

## Task 5: 校验和 round-trip 测试 + 全量验证 + README

**Files:**
- Test: `src/test/java/com/example/demo/protocol/ChecksumRoundTripTest.java`

- [ ] **Step 1: 写 round-trip 测试**

`src/test/java/com/example/demo/protocol/ChecksumRoundTripTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ChecksumRoundTripTest {

    @Test
    void checksumSurvivesRoundTrip() {
        ProtocolCodec<Ipv4HeaderWithChecksum> codec = new ProtocolCodec<>(Ipv4HeaderWithChecksum.class);

        Ipv4HeaderWithChecksum h = new Ipv4HeaderWithChecksum();
        h.setVersion(4);
        h.setIhl(5);
        h.setTotalLength(20);
        h.setTtl(64);
        h.setProtocol(17);
        h.setSourceIp(0x0A000001);
        h.setDestinationIp(0x0A000002);
        h.setHeaderChecksum(0);  // 引擎算

        byte[] out = codec.serialize(h);
        // 反序列化:校验和字段照常读出(不验证)
        Ipv4HeaderWithChecksum parsed = codec.deserialize(out);
        assertThat(parsed.getVersion()).isEqualTo(4);
        assertThat(parsed.getHeaderChecksum()).isNotZero();  // 引擎算出了值

        // 再序列化:校验和应稳定(同样的字段 → 同样的校验和)
        byte[] out2 = codec.serialize(parsed);
        assertThat(out2).containsExactly(out);
    }
}
```

- [ ] **Step 2: 运行确认通过**

Run: `./mvnw test -Dtest=ChecksumRoundTripTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 1, Failures: 0`

- [ ] **Step 3: 全量测试**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 53 + ChecksumAlgo 1 + Parity 1 + RoundTrip 1 = 56)

- [ ] **Step 4: 全量编译打包**

Run: `./mvnw package 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 5: 更新 README**

在 `README.md` 的「### Phase 2c1」之后加一节「### Phase 3」,并把「### 仍未覆盖」里的校验和项改写:
```markdown
### Phase 3(本版本新增)

- **校验和钩子** —— 实体实现 `Checksum` 接口 + `@ChecksumField` 标记,序列化时引擎自动置0→算→回写。试金石:IPv4 头校验和(16位反码求和),parity 对照 pcap4j。

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

### 仍未覆盖(后续)

- TCP/UDP 校验和(含伪首部、跨层依赖)
- CRC16(Modbus 等)
- 校验和反序列化端验证(结果存实体)
- 复杂条件(位掩码 / `&&`)
- 流重组 / 分片重组(过程性,留钩子)
```

- [ ] **Step 6: 提交**

```bash
git add src/test/java/com/example/demo/protocol/ChecksumRoundTripTest.java README.md
git commit -m "test(codec): checksum round-trip; docs: Phase 3 checksum hook"
```

---

## 完成标志

全部 Task 完成后:
- [ ] `./mvnw test` 全绿(56 个测试)
- [ ] `./mvnw package` 成功
- [ ] 校验和算法正确:全0输入(除version/ihl)→ 0xBAEB
- [ ] **硬验收**:IPv4 校验和 parity == pcap4j(整头字节一致)
- [ ] 校验和 round-trip 稳定
- [ ] Phase 1~2c1 全量回归不破
