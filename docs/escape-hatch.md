# 逃生舱(L1 / L2 / L3)

**设计原则:能用注解声明的绝不写代码;声明不了的,把「怪」隔离在最小的代码单元里,其余字段/协议仍是纯声明式。**

```
L1  声明式动态(注解 + 钩子)      ← 90% 场景
L2  字段级 FieldCodec             ← 一个字段的编码引擎不认识
L3  报文级 PacketCodec            ← 整帧都要先变换才能谈字段
```

## 怎么选

```
这个格式能不能用 @ProtocolField 的属性表达?
├─ 能 → L1(lengthField/presentIf/countField/sentinel/dispatch/DynamicSize)
├─ 只有 1~2 个字段的"编码"本身不认识(变长整数新变种/半字节逃逸/字节混淆/掩码)
│     → L2:@ProtocolField(custom = XxxCodec.class)
├─ 整帧要先做变换(字节转义/位填充/CRC 块穿插)才能进入字段解析
│     → L3:@Protocol(codec = XxxCodec.class)
└─ 连 L3 都接不住(会话协商格式/加密交叠/加密后才有结构)
      → 放弃,不属于帧格式引擎的职责
```

实测比例(18 个真实协议):**72% 纯 L1,28% 用 L2,0% 需要 L3**。

## L1:声明式动态(不是逃生舱,是基本功)

`lengthField + lengthUnit + lengthAdjust + lengthAscii`(长度族)、`presentIf`(条件)、四种循环驱动、TLV `dispatch`、`sentinel*`(终止符)见 [annotation-reference.md](annotation-reference.md)。

L1 里唯一的"写代码"是两个钩子接口:

```java
// 长度算法复杂/多字段联动时:算术长度(如字单位、长度逃逸)
public class WordUnitFrame implements DynamicSize {
    @Override
    public long computeSize(String fieldName, FieldContext ctx) {
        if (!"data".equals(fieldName)) return -1;      // -1 = 交还声明式
        return ctx.getInt("wordCount") * 32L;          // IPv4 IHL 式:字 × 32bit
    }
}

// 组装期长度回填(挂进分派树时由 StackEncoder 调)
public class PdFrame implements PayloadAware {
    @Override public void onPayload(byte[] inner) { this.frameLength = 16 + inner.length; }
}
```

WebSocket 三档长度逃逸(126→16bit、127→64bit)就是 `presentIf` + `DynamicSize` 的组合,零逃生舱代码(见 `netproto-core/src/test/.../real/ws/WebSocketRealTest.java`)。

## L2:字段级 FieldCodec

### 契约

```java
public class XxxCodec implements FieldCodec<byte[]> {
    // 读:从游标当前位置读出值(自行推进);ctx 能读"更早的字段"(长度/掩码 key/标志位)
    public byte[] read(BitCursor cursor, FieldContext ctx, int remainingBytes) { ... }

    // 写:与 read 严格互逆
    public void write(BitCursor cursor, FieldContext ctx, byte[] value) { ... }

    // value 序列化后的位宽(两遍式序列化第一遍靠它算总长,必须与 write 一致)
    public long sizeOf(byte[] value) { ... }
}
```

```java
@ProtocolField(order = 5, type = FieldType.BYTES, custom = XxxCodec.class)
private byte[] data;
```

### 规则

- 实现类须**无参构造、无状态或线程安全**(注册期创建一次,所有解码线程共享);
- `custom` 与 `size/lengthField/countField/sentinel` **互斥** —— 字段尺寸来源完全归 codec,需要的长度信息从 `ctx` 拿;
- `read/write/sizeOf` 三者一致,round-trip 是验收标准(解码值再编码必须字节相同);
- 挂上后该字段完全旁路反射引擎,但**协议仍在分派树、UI、组装面板里正常工作**。

### 内置

`VarintCodec`(LEB128,Protobuf/MQTT Remaining Length 同款)直接可用:
`@ProtocolField(order = 3, custom = VarintCodec.class) private Long remainingLength;`

### 真实用例(均在 `netproto-core/src/test/.../protocols/real/`)

| codec | 协议 | 接管什么 |
|---|---|---|
| `QuicVarintCodec` | QUIC | 首 2bit 决定 1/2/4/8 字节宽的前缀定长 varint(RFC 9000 §16 四向量验证) |
| `Plus33DataCodec` | DL/T 645 | 数据域逐字节 +0x33/-0x33 传输混淆(长度从 ctx 的 len 拿) |
| `MaskedPayloadCodec` | WebSocket | payload 与 maskKey mod-4 循环 XOR(key 从 ctx 拿) |
| `BerLengthCodec` | BER/DER | 长形式长度(0x81/0x82 前缀),拒绝不定长 0x80 |
| nibble codec | CoAP | option 的半字节 delta/length + 13/14 两级逃逸(值 +13/+269) |
| `MqttSnLengthCodec` | MQTT-SN | Length=0x01 时转义为 3 字节总长 |

## L3:报文级 PacketCodec

**整个协议**的编解码交给手写实现,反射式引擎完全旁路;但通过 `@BindOn` 照常挂回分派树,栈解析照常下降到它。

```java
@Protocol(id = "ppp-async", codec = StuffedFrameCodec.class)
@BindOn(parent = "serial", when = "framing == 1")
class PppAsyncFrame { }

public class StuffedFrameCodec implements PacketCodec<PppAsyncFrame> {
    private final ProtocolCodec<PppAsyncFrame> inner = new ProtocolCodec<>(PppAsyncFrame.class);

    @Override public PppAsyncFrame decode(byte[] data, int offset, int length) {
        byte[] unescaped = unescape(data, offset, length);      // 0x7D XOR 0x20 还原
        return inner.decode(unescaped, 0, unescaped.length);     // 变换后再走声明式内芯
    }
    @Override public byte[] encode(PppAsyncFrame p) { /* 编码 + 转义 */ }
    @Override public int headerBytes() { return -1; }            // 叶子协议:不向下分派;-1 之外的值=子层起始偏移
}
```

适用:PPP/SLIP 字节转义、HDLC 位填充、DNP3 的每 16 字节穿插 CRC —— 共同点是**帧界/偏移在变换前不成立**。参考实现:`netproto-core/src/test/.../core/BoundaryEscapeHatchTest.java` 的 `StuffedFrameCodec`。

典型结构是「L3 壳 + L1 芯」:变换(转义/解填充)用 20 行手写,内部结构仍然声明式。

## 边界(明确不做)

位填充/字节转义进注解 DSL、LSB-first 位序选项、值域类型族(Protobuf/MessagePack)、会话状态机(Kermit 协商/XModem 'C')、加密区间/MIC、绝对偏移寻址 —— 这些属于帧外状态或变换层,由 L3 或上层承担;论证见 [format-boundary-report.md](format-boundary-report.md)。
