# 通用协议编解码引擎 — Phase 3 设计(校验和钩子)

- 状态:草案(待用户复审)
- 日期:2026-06-30
- 试金石协议:IPv4 头校验和(16 位反码求和)
- 范围:`Checksum` 接口 + `@ChecksumField` 注解,序列化端自动算校验和

---

## 1. 背景与目标

### 1.1 现状(Phase 1 + 2a + 2b + 2d + 2e + 2c1 之后)

引擎已支持位字段、长度引用、嵌套、条件、字符串、count/sentinel/length 驱动集合、枚举、位标志、异质 TLV。但**校验和/CRC**不支持——这是 8 类短板里最后一块、也是最有价值的一项(协议没有正确校验和,包会被网络丢弃)。

校验和本质上是**过程性**的:算法各异(IPv4 反码求和、TCP/UDP 含伪首部、Modbus CRC16),覆盖范围难以声明式表达。Phase 3 提供**钩子框架**(用户实现算法),引擎在"何时算、放哪"上提供支持——这是从最初 brainstorm 就明确的边界(校验和不能纯声明式优雅表达)。

### 1.2 Phase 3 目标

支持**序列化端自动算校验和**:
- 实体实现 `Checksum` 接口(提供计算逻辑)
- `@ChecksumField` 标记哪个字段是校验和
- 序列化时引擎自动:置0 → 算 → 回写
- 试金石:IPv4 头校验和(16 位反码求和),parity 对照 pcap4j

做完生成的 IP 包校验和与 pcap4j 一致(网络可接受)。

### 1.3 Phase 3 不做(留后续)

| 不含 | 留给 |
|---|---|
| 反序列化端验证(C1:结果存实体) | 后续 |
| TCP/UDP 校验和(含伪首部、跨层依赖) | 后续 |
| CRC16(Modbus 等,算法不同需独立接口) | 后续 |

**诚实边界**:Phase 3 只做 IPv4 头校验和(单层、无伪首部、反码求和)。只做序列化端(算并填入),不做反序列化端验证。用户若想验证,可手动调 `compute` 比对。

---

## 2. 关键设计抉择

### 2.1 校验和用钩子接口(实体可选实现,同 DynamicSize 同构)

```java
public interface Checksum {
    long compute(String fieldName, byte[] serialized);
}
```

实体实现它。`compute` 收到的是**整包序列化后的字节(校验和字段已被引擎置 0)**,返回校验和值(引擎截断到字段位数)。返回 -1 表示不接管该字段(走普通字段路径)。与 `DynamicSize` 完全同构的认知模型。

### 2.2 序列化两遍:置0 → 算 → 回写

校验和字段依赖"其他字段的值",无法和其他字段一起一遍写完。流程:
1. 第一遍:序列化所有字段;遇 `@ChecksumField` → **强制写 0**(记下该字段的字节偏移)
2. 第二遍:对每个 `@ChecksumField` 字段 → `compute(field, 整包字节)` → 截断到字段位数 → 按偏移回写

**关键**:引擎在第一遍把校验和字段强制置 0,钩子收到的字节校验和字段已是 0,钩子直接对全包求和取反即可,不用自己处理置 0。

### 2.3 反序列化不验证(C2)

反序列化照常读出校验和字段的值,不验证。校验和的核心价值在序列化端(生成的包要正确);验证端(结果存哪)涉及额外设计,后续加。用户若想验证,可手动调 `compute` 比对。

---

## 3. 注解/接口 DSL(零 FieldType 增量)

**关键**:校验和字段是普通 INT 字段(16位),只是被 `@ChecksumField` 标记 + 实体实现 `Checksum` 接口。**`FieldType` 不加新枚举值,`@ProtocolField` 不改。**

| 新增 | 说明 |
|---|---|
| `Checksum` 接口(`long compute(field, serializedBytes)`) | 校验和计算钩子(同 DynamicSize) |
| `@ChecksumField` 注解(字段级,无属性) | 标记校验和字段 |

引擎识别:实体实现 `Checksum` + 字段标 `@ChecksumField` → 序列化时特殊处理(置0→算→回写)。

---

## 4. 新增类型

### 4.1 `Checksum` 接口(新建)

```java
package com.example.demo.protocol.core;

/** 校验和钩子:实体可选实现,提供校验和计算逻辑。 */
public interface Checksum {

    /**
     * 计算校验和字段的值。
     * @param fieldName  哪个字段要算校验和(@ChecksumField 标记的字段名)
     * @param serialized 整个实体序列化后的字节(校验和字段已被引擎置 0)
     * @return 校验和值;返回 -1 表示不接管该字段(走普通路径)
     */
    long compute(String fieldName, byte[] serialized);
}
```

### 4.2 `@ChecksumField` 注解(新建)

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

---

## 5. 序列化流程(改动,集中在 serialize)

```
serialize(obj):
  若 obj 实现 Checksum:
    收集 @ChecksumField 字段列表
    第一遍:序列化所有字段;遇 @ChecksumField → 强制写 0(记下字节偏移)
    第二遍:对每个 @ChecksumField 字段:
        取整包字节 → compute(field, bytes) → 截断到字段位数
        按该字段字节偏移,回写进字节
  否则:照常序列化(零改动)
```

反序列化:**零改动**(C2——不验证)。

### 5.1 字节偏移记录与两遍结构对齐

现有 `serialize` 已是两遍结构:**第一遍算 totalBits**(不写字节),**第二遍用 BitCursor 写所有字段**。Phase 3 的改动集中在第二遍:
- 第二遍写字段时,遇 `@ChecksumField` → 强制写 0(而非对象当前值),并记录该字段的起始字节偏移(= 写入前的 cursor.bitOffset() / 8)
- 第二遍写完后,新增第三步:对每个 `@ChecksumField` → `compute(field, cursor.bytes())` → 截断 16 位 → 按记录的偏移回写 2 字节到 `cursor.bytes()`

校验和字段是字节对齐的(16位),偏移 = bitOffset / 8,回写 2 字节。

---

## 6. 向后兼容(硬指标)

| Phase 1~2c1 代码 | Phase 3 后 |
|---|---|
| `Ipv4Header`(无校验和钩子)、MyProtocol、所有现有实体 | 零改动,全绿 |
| 校验和是新增能力 | 只有 `@ChecksumField` + 实现 `Checksum` 的实体才走校验和路径 |
| `@ProtocolField` / `FieldType` | 完全不变(Phase 3 不加注解到 ProtocolField、不加枚举值) |

**关键兼容点**:校验和路径只在实体实现 `Checksum` 接口时触发。普通 int 字段、所有现有实体不受影响。Phase 3 纯增量。

---

## 7. 验收标本:IPv4 头校验和

```java
@Data @ProtocolPacket(port = 0)
public class Ipv4HeaderWithChecksum implements Checksum {
    @ProtocolField(order=1,  size=4)   private int version;
    @ProtocolField(order=2,  size=4)   private int ihl;
    @ProtocolField(order=3,  size=8)   private int tos;
    @ProtocolField(order=4,  size=16)  private int totalLength;
    @ProtocolField(order=5,  size=16)  private int identification;
    @ProtocolField(order=6,  size=3)   private int flags;
    @ProtocolField(order=7,  size=13)  private int fragmentOffset;
    @ProtocolField(order=8,  size=8)   private int ttl;
    @ProtocolField(order=9,  size=8)   private int protocol;
    @ProtocolField(order=10, size=16)
    @ChecksumField
    private int headerChecksum;
    @ProtocolField(order=11, size=32)  private int sourceIp;
    @ProtocolField(order=12, size=32)  private int destinationIp;

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"headerChecksum".equals(field)) return -1;
        return onesComplementSum(serialized);  // serialized 里校验和字段已置 0
    }

    // IPv4 16 位反码求和
    private static long onesComplementSum(byte[] data) {
        long sum = 0;
        for (int i = 0; i + 1 < data.length; i += 2) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
        }
        if ((data.length & 1) != 0) {  // 奇数字节,末尾补 0
            sum += (data[data.length - 1] & 0xFF) << 8;
        }
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (~sum) & 0xFFFF;
    }
}
```

---

## 8. 测试与验收策略

| 测试 | 验证 |
|---|---|
| `ChecksumAlgorithmTest` | 反码求和算法正确性(手构已知输入→已知输出,如全 0 → 0xFFFF) |
| `Ipv4ChecksumParityTest` | **硬验收**:我们的校验和 == pcap4j 的校验和(同一 IP 包) |
| `ChecksumRoundTripTest` | 校验和 round-trip:序列化→反序列化,校验和字段保持 |
| **Phase 1~2c1 全量回归** | 53 个测试全绿 |

**验收边界**:Phase 3 只做 IPv4 头校验和(单层、无伪首部)。TCP/UDP 校验和留后续。

---

## 9. Phase 3 交付清单

- [ ] `Checksum` 接口(`long compute(field, serializedBytes)`)
- [ ] `@ChecksumField` 注解(字段级,无属性)
- [ ] `ProtocolCodec.serialize`:Checksum 实体的两遍序列化(置0→算→回写偏移)
- [ ] `Ipv4HeaderWithChecksum` 实体(实现 Checksum + 反码求和)
- [ ] 3 类测试 + Phase 1~2c1 回归
