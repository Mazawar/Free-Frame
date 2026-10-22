# 注解语言参考

一个 POJO + 注解描述一个二进制协议:字段顺序、位宽、端序、变长、条件、循环、TLV 分派全部声明式;同一份注解同时驱动**解析**与**组装**,round-trip 是验收标准。

> 逃生舱(编码引擎不认识的格式)见 [escape-hatch.md](escape-hatch.md);协议栈分派见 [protocol-stack.md](protocol-stack.md)。

## 1. `@Protocol` —— 标记一个协议报文类

| 属性 | 默认 | 说明 |
|---|---|---|
| `id` | 必填 | 分派树节点名,全局唯一(重复注册启动即失败) |
| `name` | 取 id | 显示名 |
| `builtin` | false | 内置协议标记(仅 UI 徽标) |
| `group` | "" | UI 侧栏分组(子协议只声明子组名,完整路径沿 `@BindOn` 父链推导,支持多级) |
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
| `endian` | BIG | 整数字节序;LITTLE 仅支持整字节的定长整数与 FLOAT。**校验和字段回写同样应用端序** |
| `type` | 按字段类型推断 | `INT` / `UNSIGNED`(≤63bit) / `BYTES` / `STRING` / `NESTED` / `LIST` / `LIST_TLV` / `FLOAT`(32/64) / `BCD`(每 4bit 一位十进制) |
| `lengthField` | "" | 变长字段:引用**更早**字段的值作长度(前向引用注册期拒绝) |
| `lengthUnit` | BYTES | `BYTES` / `BITS`(位数非 8 倍数会被 readBytes 拒绝) |
| `lengthAdjust` | 0 | 长度偏移:字段字节长度 = lengthField 值 + adjust(负值用于「总长含头」类口径,如 `lengthAdjust=-3`) |
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
// ② 字节计数驱动(Modbus byteCount:个数 = 字节/元素定长)
@ProtocolField(type = LIST, countField = "byteCount", countUnit = CountUnit.BYTES, elementClass = Reg16.class)
// ③ 终止符驱动(单字节 / "\r\n" / 元素内字段哨兵)
@ProtocolField(type = LIST, sentinel = 0, elementClass = Label.class)
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

编码期一致性:长度字段推导出的字节数必须与实际 payload 相符,否则报 `implies N bits but value has M bits`(组装时由 `PayloadAware.onPayload(inner)` 回填长度字段,见 protocol-stack.md)。普通 BYTES/STRING 的 lengthField 同样有一致性校验。

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

- 两遍式:序列化时该字段写 0 → 调 `compute` → 按字段 size 截断回写(**应用字段 endian**,Modbus 低字节在前直接声明 LITTLE 即可);
- 校验范围自定(切片/伪头均可,IPv4 头校验和即按 IHL 切片);
- 多个 `@ChecksumField` 各自独立回写(限制:后一个的算法不能依赖前一个的**已写入**值)。

## 6. 表达式小语言(presentIf / when 共用)

```
orExpr := andExpr ('||' andExpr)*        andExpr := unary ('&&' unary)*
unary  := '!' unary | cmp                cmp := operand (('=='|'!='|'<'|'<='|'>'|'>=') operand)?
operand := '(' orExpr ')' | 标识符 | 数字(十进制/0xHH,可负)
标识符:字段名,或位索引 name[n](按字段声明 size 从 MSB 数第 n 位;动态长度字段回退 Java 类型宽度)
```

无算术/位运算/字符串比较 —— 需要 `a+b`、`x&mask` 之类的长度联动用 `DynamicSize` 钩子或 1bit 拆分。

## 7. 注册期校验(fail-fast)

违反即拒绝注册,不等运行期:未知/前向的 lengthField/countField/presentIf 引用;数值字段 size 越界(0、>64);字节类定长非 8 倍数;LITTLE 非整字节;sentinel 与 count/length 互斥;untilEnd 元素含 @Payload;LIST 元素最后字段无自定界;group 字段不相邻/不对齐;dispatch 类不存在。
