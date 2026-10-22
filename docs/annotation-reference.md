# 注解语言参考

一个 POJO + 注解描述一个二进制协议:字段顺序、位宽、端序、变长、条件、循环、TLV 分派全部声明式;同一份注解同时驱动**解析**与**组装**,round-trip 是验收标准。

> 逃生舱(编码引擎不认识的格式)见 [escape-hatch.md](escape-hatch.md);协议栈分派见 [protocol-stack.md](protocol-stack.md)。

## 0. 一分钟看懂:注解如何对应字节

以 Modbus RTU 读保持寄存器请求(经典帧 `11 03 00 6B 00 03 76 87`)为例:

```text
线上字节   11      03      00 6B            00 03            76 87
           ┆       ┆       ┆                ┆                ┆
字段       addr    func    startAddr        qty              crc
@注解      size=8  size=8  size=16          size=16          size=16, endian=LITTLE, @ChecksumField
值         0x11    3(读)   107              3 个             CRC-16(低字节在前)
```

```java
@Data
@Protocol(id = "modbus-req")
class ReadHoldingReq implements Checksum {
    @ProtocolField(order = 1, size = 8)                       private int addr;
    @ProtocolField(order = 2, size = 8)                       private int func = 3;
    @ProtocolField(order = 3, size = 16)                      private int startAddr;
    @ProtocolField(order = 4, size = 16)                      private int qty;
    @ProtocolField(order = 5, size = 16, endian = Endian.LITTLE)
    @ChecksumField                                           private int crc;

    @Override public long compute(String f, byte[] serialized) {
        return crc16Modbus(serialized, 0, serialized.length - 2);   // 校验范围 = CRC 前全部
    }
}
```

这段声明同时回答了:字段怎么排、多宽、什么端序、校验算哪段、校验和怎么放 —— 解析和组装用同一份答案。

## 1. `@Protocol` —— 标记一个协议报文类

| 属性 | 默认 | 说明 |
|---|---|---|
| `id` | 必填 | 分派树节点名,全局唯一(重复注册启动即失败) |
| `name` | 取 id | 显示名 |
| `builtin` | false | 内置协议标记(仅 UI 徽标) |
| `group` | "" | UI 侧栏分组(子协议只声明子组名,完整路径沿 `@BindOn` 父链推导,支持多级嵌套) |
| `internal` | false | 中间产物(公共头/纯结构层):不进侧栏过滤、不进发包目标;解码树仍展示 |
| `codec` | 反射式 | 报文级逃生舱(L3),指定后整个协议的编解码交给手写 `PacketCodec` |

类要求:无参构造(可包私有),字段用 Lombok `@Data` 或手写 getter/setter 均可。

## 2. `@BindOn` —— 挂到父协议(分派规则)

```java
@Protocol(id = "my-app")
@BindOn(parent = "udp", when = "dstPort == 9999 || srcPort == 9999")
@BindOn(parent = "ethernet", when = "etherType == 0x88B5")   // 可重复:多父挂载
class MyProtocol { }
```

| 属性 | 说明 |
|---|---|
| `parent` | 父协议 id;父层解析后从其头部之后继续下降 |
| `when` | 条件表达式,只能引用**父协议**的字段;支持 `== != < <= > >= && \|\| ! ( )` 与十进制/`0x` 字面量;未解析字段使整个表达式按 false 处理(宽松模式,不抛异常) |
| `priority` | 同父多绑定同时命中时高者优先;平级取注册顺序(启动告警) |

## 3. `@ProtocolField` —— 字段声明(核心)

| 属性 | 默认 | 说明 |
|---|---|---|
| `order` | 必填 | 字段排列顺序 |
| `size` | -1 | 位数(任意 1..64,不必 8 的倍数,允许跨字节;`-1`=动态)。数值字段必须 1..64;BYTES/STRING/NESTED 定长须 8 的倍数(128bit 用 BYTES) |
| `endian` | BIG | 整数与 FLOAT 字节序;LITTLE 仅支持整字节定长。**校验和字段回写同样应用端序** |
| `type` | 按字段类型推断 | `INT` / `UNSIGNED`(≤63bit) / `BYTES` / `STRING` / `NESTED` / `LIST` / `LIST_TLV` / `FLOAT`(32/64) / `BCD`(每 4bit 一位十进制) |
| `lengthField` | "" | 变长字段:引用**更早**字段的值作长度(前向引用注册期拒绝) |
| `lengthUnit` | BYTES | `BYTES` / `BITS`(位数非 8 倍数会被拒绝) |
| `lengthAdjust` | 0 | 长度偏移:字段字节长度 = lengthField 值 + adjust(负值用于「总长含头」类口径) |
| `lengthAscii` | false | lengthField 值是 ASCII 十进制文本(ISO 8583 LLVAR:两位 `"12"`) |
| `presentIf` | "" | 条件字段,满足才出现;全语法(`len>0`、`ver>=2 && x==1`)、位索引(`bitmap[3]==1`,按**声明 size** 从 MSB 数);禁前向引用 |
| `charset` | UTF-8 | STRING 字符集(GBK/GB18030 等均可) |
| `countField` | "" | LIST 元素个数,引用更早字段 |
| `countUnit` | ELEMENTS | `ELEMENTS`(个数)/ `BYTES`(计数字段是**字节数**,元素须定长,如 Modbus byteCount) |
| `elementClass` | void | LIST/LIST_TLV 元素类型(必须是 `@Protocol` 实体);`count=-1` = null 数组(Kafka 语义,空列表) |
| `sentinel` / `sentinelStr` | -1 / "" | 终止符驱动(单字节值 / 多字节串如 `"\r\n"`),与 countField/lengthField 互斥 |
| `sentinelOn` + `sentinelValue` | — | 元素内终止:peek 元素的某字段,等于该值则 LIST 结束 |
| `untilEnd` | false | 循环·耗尽驱动:读到本层末尾(元素须自定边界) |
| `tlvEndMarker` | -1 | 异质 TLV 的结束哨兵(如 DHCP 的 0xFF) |
| `dispatch` | {} | 异质 TLV 分派表:`{"1=SubnetMask", "3=Router"}`(简单名按字段所在包解析);未知 type 自动跳过其 value |
| `enumClass` / `flagClass` | void | 枚举(实现 `ProtocolEnum`,未知值返回 `UnknownEnumValue` 保留原值)/ 位标志(`Set<E>` 元素实现 `ProtocolFlag`) |
| `custom` | void | **L2 逃生舱**:字段级自定义编解码器,与 size/lengthField/countField/sentinel 互斥 |
| `group` / `label` | "" | 展示分组(Wireshark 式命名组,组内字段按 order 相邻且字节对齐)/ 展示名 |

### 四种循环驱动一览

```java
// ① count 驱动(个数)
@ProtocolField(type = LIST, countField = "itemCount", elementClass = Item.class)
// ② 字节计数驱动(Modbus byteCount:个数 = 字节 / 元素定长)
@ProtocolField(type = LIST, countField = "byteCount", countUnit = CountUnit.BYTES, elementClass = Reg16.class)
// ③ 终止符驱动(单字节 / "\r\n" / 元素内字段哨兵)
@ProtocolField(type = LIST, sentinel = 0, elementClass = Label.class)          // DNS 标签,根 0x00
@ProtocolField(type = LIST, sentinelOn = "type", sentinelValue = 0xFF, elementClass = Entry.class)
// ④ 耗尽驱动(读到层尾)
@ProtocolField(type = LIST, untilEnd = true, elementClass = Tlv16Elem.class)
```

## 4. `@Payload` —— 载荷与帧尾字段

**两种模式:**

```java
// A. 裸 @Payload:取本层剩余全部字节,后面不能再声明字段
@Payload
private byte[] payload;

// B. 长度驱动 + 尾随字段(帧尾 CRC/结束符):按 lengthField 截断读,其后可继续声明
@Payload
@ProtocolField(order = 7, lengthField = "len", lengthAdjust = -14)
private byte[] body;
@ProtocolField(order = 8, size = 16, endian = Endian.LITTLE) @ChecksumField
private int crc;
```

编码期一致性:长度字段推导出的字节数必须与实际 payload 相符,否则报
`implies N bits but value has M bits`(组装时由 `PayloadAware.onPayload(inner)` 回填长度字段)。
普通 BYTES/STRING 的 `lengthField` 有同样的一致性校验。

## 5. `@ChecksumField` + `Checksum` 接口

```java
public class ModbusRtu implements Checksum {
    @Override
    public long compute(String fieldName, byte[] serialized) {
        // serialized = 整帧序列化字节,本字段位置已被置 0
        // 返回校验值;-1 表示不接管
        return crc16(serialized, 0, serialized.length - 2);
    }
}
```

- **两遍式**:序列化时该字段写 0 → 调 `compute` → 按字段 size 截断回写(应用字段 endian,Modbus 低字节在前直接声明 LITTLE);
- **范围自定**:切片/伪头均可(IPv4 头校验和即按 IHL 切片;跨层伪头也可在钩子里拼);
- **多校验和**:多个 `@ChecksumField` 各自独立回写(限制:后一个的算法不能依赖前一个**已写入**的值)。

## 6. 表达式小语言(presentIf / when 共用)

```
orExpr  := andExpr ('||' andExpr)*        andExpr := unary ('&&' unary)*
unary   := '!' unary | cmp                cmp     := operand (('=='|'!='|'<'|'<='|'>'|'>=') operand)?
operand := '(' orExpr ')' | 标识符 | 数字(十进制/0xHH,可负)
标识符:字段名,或位索引 name[n]
```

- 位索引 `name[n]`:按字段**声明 size** 从 MSB 数第 n 位(8bit 字段的 bit2 = `name[6]`;
  32bit 字段最高位 = `name[1]`);动态长度(-1)字段回退 Java 类型宽度;
- 无算术/位运算/字符串比较 —— 需要 `a+b`、`x&mask` 的长度联动用 `DynamicSize` 钩子或 1bit 拆分;
- 严格/宽松两模式:presentIf 遇未知字段抛异常(定义错误);when 遇未解析字段整体为 false。

## 7. 常见组合速查

| 需求 | 写法 |
|---|---|
| 长度 = 总帧长(含长度字段自身) | `lengthField` + `lengthAdjust = -N` |
| 帧尾 CRC(公共头 + 类型分派 + 尾随) | 长度驱动 `@Payload` + 尾随 `@ChecksumField`(见 §4-B) |
| 位图驱动字段出现(ISO 8583) | `presentIf = "bitmap[1]==1"`(按声明 size 从 MSB 数) |
| 一字节内「标志位 + 7bit 计数」(IEC 104 VSQ) | 拆两个位字段:`sq(1)` + `count(7)`,`countField="count"` |
| 计数字段是字节数(Modbus byteCount) | `countUnit = CountUnit.BYTES` |
| 文本长度前缀(LLVAR) | `lengthAscii = true` |
| 变长整数(LEB128) | `custom = VarintCodec.class` |
| 长度单位是字(IPv4 IHL/FlexRay) | `DynamicSize` 钩子 `count * 32` |
| 长度逃逸(WebSocket 126/127) | `presentIf` 三态字段 + `DynamicSize`(见 escape-hatch.md) |
| 16bit type 的宽头 TLV(TLS/SCTP 式) | LIST + 实体组合(`type(16)+len(16)+value`),不用 LIST_TLV(头固定 8/8) |
| 帧尾结束符(`\r\n`) | `sentinelStr = "\r\n"` |
| 递归嵌套(DER 式) | 自引用 NESTED 字段 + `presentIf`(深度由数据驱动) |

## 8. 注册期校验(fail-fast)

违反即拒绝注册,不等运行期:未知/前向的 `lengthField`/`countField`/`presentIf` 引用;
数值字段 size 越界(0、>64);字节类定长非 8 倍数;LITTLE 非整字节;sentinel 与 count/length 互斥;
untilEnd 元素含 `@Payload`;LIST 元素最后字段无自定界;group 字段不相邻/不对齐;dispatch 类不存在。

## 9. FAQ

**Q:位索引到底从哪边数?**
按声明 size 从 **MSB**(最高位)数:`bitmap[1]` = 最高位,`bitmap[8]` = 8bit 字段的最低位。想取 bit2(值 0x04)写 `bitmap[6]`。

**Q:长度能引用后面的字段吗(尾部长度)?**
不能,前向引用注册期拒绝 —— 这是解码顺序的硬约束。调整字段 order 或用钩子。

**Q:count = -1 是什么?**
null 数组语义(Kafka `topicsCount=-1` 同款):空列表,round-trip 保留 -1。小于 -1 视为垃圾,解码报错。

**Q:解码后字段值是 0,怎么区分「线上就是 0」和「字段没出现」?**
不要用值判断 —— 用字节区间(`lastFieldRanges`,无区间 = 未解析)。absent 字段保持 Java 默认值是假值陷阱。

**Q:为什么 8bit 字段读 0xFF 得到 255 而不是 -1?**
按 **Java 字段类型**符号扩展:`int` 字段零扩展(255),要负数声明 `byte` 字段(-1)。

**Q:LE 字段报「requires a fixed size in whole bytes」?**
位字段没有字节序(位序固定 MSB-first)。需要 LE 语义就拆 1bit 字段,或保持整字节。

**Q:组装时报 `implies N bits but value has M bits`?**
长度字段值与实际数据长度不一致。实现 `PayloadAware.onPayload` 自动回填,或手工设置正确的长度字段。

**Q:LIST 元素报「no self-boundary」?**
元素的最后一个字段必须能自定界(有 `size` / `lengthField` / 本身是 LIST),否则引擎无法切分元素。

**Q:非字节对齐的 BYTES 字段(3bit 标志后跟 2 字节数据)?**
支持 —— 引擎做位级位移读写,编解码对称(见 `BoundaryBitAlignmentTest`)。

**Q:TLV 的 type/length 是 16bit 怎么办?**
`LIST_TLV` 头固定 8bit/8bit;宽头用「LIST + 元素实体(type16+len16+value lengthField)」组合表达,见速查表。
