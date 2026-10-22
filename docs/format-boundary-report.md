# 帧格式组装能力边界测试报告

> 2026-10-22 · 方法:双路后台调研(工业/电力/车载 25 个协议 + IoT/网络/通用 34 个协议,归并出 ~95 项格式机制)× 引擎源码盘点 × 53 个边界测试实测打点。
> 产出:`netproto-core` 9 个 `Boundary*Test` 全绿;全仓回归 209 个测试全绿(core 170 / web 16 / demo 23)。
> 当日修复:实测发现的 9 项缺陷全部修复(P0 三项 + P1 六项),见第二节;代码未提交。

## 一、结论

**引擎在「结构层」机制覆盖约 80%**:长度族(前缀/自包含/剩余/含头调整/BITS 单位/ASCII 长度/字单位钩子)、条件族(presentIf + 位索引)、循环族(count/countBytes/三种 sentinel/untilEnd)、位打包(任意宽跨字节,MSB-first)、混合字节序、BCD/FLOAT/GBK/128bit、递归嵌套、校验和钩子(任意算法/范围/多校验)、分派树、组装自动接线——均已实测通过,含 Modbus RTU 端到端(CRC-16 标准向量 0x4B37 验证)、IEC104 VSQ 位拆、ISO 8583 存在位图、WebSocket 三档长度逃逸、SCTP 对齐填充、ARP 双前序长度、HART 双地址形态、递归 DER 式节点。

未覆盖的 ~20% 集中在四族,**全是帧外状态或变换层,DSL 天然不该管**:①位流/字节填充(HDLC、PPP、DNP3 CRC 穿插)②值域区间类型族(Protobuf/MessagePack)③会话协商格式(Kermit/XModem/WebSocket 分片)④加密交叠(LoRaWAN/BLE/802.15.4/QUIC)。前三族已验证 L3 逃生舱可接(PPP 转义 L3、BER 长形式 L2、LEB128 内置)。

## 二、实测发现(按严重度)

### 引擎缺陷/不一致(P0,正确性)—— ✅ 三项已于当日修复
1. ~~**非对齐 BYTES/STRING/NESTED 解码静默错位**~~ → **已修复**:`BitCursor.readBytes/writeBytes` 非对齐路径改为位级位移读写,编解码对称,非对齐 BYTES 字段可正确 round-trip(测试钉死手算位布局 A2 46 80)。
2. ~~**FLOAT 不应用 endian**~~ → **已修复**:`readValue/writeValue` 的 FLOAT 分支按字段 endian 做字节反转,LE 浮点(Modbus 寄存器形态)round-trip 正确。
3. ~~**普通 BYTES 的 lengthField 与实际长度不一致时静默毒数据**~~ → **已修复**:序列化第一遍对 BYTES/STRING(lengthField 驱动)做一致性校验,与 @Payload 模式同标准,报文含 implied/actual 位数;新增正反用例(BYTES/LLVAR)。

### 陷阱/校验缺口(P1)—— ✅ 六项已于当日修复
4. ~~**位索引按 Java 类型宽度而非声明 size**~~ → **已修复**:`Expr.resolveBitIndex` 增加声明位宽解析(presentIf 侧查 codec 字段表、when 侧查父协议注解),size=32 的 long 字段 `[1]` 即最高位;动态长度(-1)回退 Java 宽度。
5. ~~**presentIf 注册校验只认「字段==常量」形态**~~ → **已修复**:校验改走 `Expr.compile + collectIdents` 全语法,`>`/`>=`/`!=`/`&&`/`||` 均可注册;同时补了前向引用禁令(引用更晚字段注册期拒绝,消除序列化可行/解析必炸的不对称)。
6. ~~**@ChecksumField 回写忽略字段 endian**~~ → **已修复**:回写前按字段 endian 反转,LE 校验和(低字节在前)编解码对称;Modbus 式预交换 workaround 不再必需。
7. ~~**负计数静默空列表**~~ → **已修复**:`-1` 明确为 null 数组语义(Kafka 兼容,空列表);小于 -1 的垃圾计数干净报错。
8. ~~**size=0 / size>64 注册放行**~~ → **已修复**:注册期校验——数值字段 size 必须 1..64,字节类字段(BYTES/STRING/NESTED 定长)必须 8 的倍数,0/负数非法。
9. ~~**畸形输入裸 AIOOBE 包装**~~ → **已修复**:`BitCursor` 位/字节读写统一越界检查,报文含「需要 N 位/字节 + 剩余量」(`bit/byte read past end`),不再 ArrayIndexOutOfBounds。

### 验证通过(能力确认)
- L2/L3 逃生舱充分性:BER 长形式(L2)、PPP 字节转义(L3)、LEB128(内置 VarintCodec)、字单位长度/长度逃逸/对齐填充(DynamicSize)。
- 递归嵌套:深度由数据驱动,畸形输入按字节耗尽终止,不死循环。
- 计数/长度超卖:毫秒级失败,不逐元素空转、不预分配。
- 全前缀截断扫描(0..n-1 每个截断点):全部拒绝,无部分解析成功。
- 终止符缺失 / varint >64bit / BER 不定长:干净失败,报文明确。

## 三、建议补(P2,按需)
- `LengthUnit.WORDS`(2/4 字节字):IPv4 options、FlexRay、RTP/RTCP、SCTP 一族,现需 DynamicSize 手搓。
- 内置 CRC 工具族(CRC16-Modbus/CCITT/DNP3/XMODEM、CRC32c):现每协议手搓 compute()。
- LIST_TLV 头位宽可配(16bit type/length:TLS 扩展/SCTP 参数式),现固定 8/8。

## 四、明确不做(没必要)
- 位填充/字节转义进 DSL——L3 已验证够用,进 DSL 复杂度爆炸。
- LSB-first 位序选项(802.15.4/CAN 位流)——需求出现再说,LE 字节序已覆盖大半。
- Protobuf/MessagePack 值域类型族——目标是协议帧引擎,不是序列化库。
- 会话状态机(Kermit 协商、XModem 'C' 选 CRC、WebSocket 分片)——帧后处理/传输层职责。
- DNS 压缩指针 DSL 化——已有 L2 惯例,编码端需字典,图结构性价比低。
- 加密区间/MIC(AEAD/CMAC)——安全栈独立关注点。
- 绝对偏移寻址字段、尾部长度(前向引用)——禁令是有意设计,真实协议罕见。

## 五、兜底清单(修复后)
| 畸形输入 | 现状 | 评价 |
|---|---|---|
| 长度/计数超卖 | `bit/byte read past end`(含需求量与剩余量) | ✓ 干净可读 |
| 终止符缺失 | 干净 IllegalStateException | ✓ |
| 全前缀截断 | 全部拒绝 | ✓ |
| 0 字节元素 × 大计数 | 线性空转(count 无上限) | 建议元素耗 0 字节即 break(untilEnd 已有同款防护) |
| 递归无界 | 输入长度约束深度,异常终止 | ✓(无显式上限,可接受) |
| 计数 = -1 | 空列表(null 数组,Kafka 语义) | ✓ 设计语义 |
| 计数 < -1 | 干净报错 | ✓ |
| 超大帧(>2^31 bit) | 未设防 | 与已知「无上限」缺口一致 |

## 六、协议覆盖度明细
- **工业/电力/车载(25)**:纯声明式或+小钩子 ~18(Modbus RTU/ASCII/TCP、DL/T 645(+33 需 L2)、CJ/T 188、IEC 101/104、HART、DoIP、SOME/IP、TPKT/COTP/S7、BACnet MS/TP、PROFINET DCP、EtherCAT 静态、CAN/LIN/FlexRay、ISO-TP、OPC UA、MMS/BER);需 L3 ~5(DNP3、HDLC 类、GOOSE 全 BER、位填充类);不建议 2(EtherCAT process-on-the-fly、真位流)。
- **IoT/网络/通用(34)**:可表达 ~2/3(Ethernet/VLAN/ARP/IPv4/IPv6 基本头/TCP 部分/UDP/ICMP/DHCP/DNS(L2)/MQTT/MQTT-SN/LoRaWAN 结构/SCTP/XModem/RTP/TLS 结构/WebSocket 长度/BSON 结构/DER(L2) 等);不可表达集中在 Protobuf、MessagePack、QUIC 加密交叠、802.15.4 位序、HDLC/PPP/SLIP(→L3)、Kermit/ZModem。

## 附:调研原始产出
两路调研(机制矩阵 M1-M50 / M1-M45、十大怪癖榜、验证 URL)见会话记录;如需长期保存可归档至 docs/。

## 七、真实协议验证(2026-10-22 第二轮)

`netproto-core/src/test/java/com/netproto/protocols/real/` 下 **18 个协议族 / 46 个用例**,全部权威字节向量断言 + round-trip,全仓 255 个测试全绿(core 216 / web 16 / demo 23):

| 领域 | 协议 | 向量来源 | 表达方式 |
|---|---|---|---|
| 电力/工控 | Modbus RTU | CRC-16/MODBUS 标准向量 + 经典帧 11 03 006B 0003 7687 | 纯声明式 + Checksum 钩子(LE 字段直驱) |
| | Modbus TCP | MBAP 经典帧 | 纯声明式 |
| | DL/T 645-2007 | 规约读通信地址帧 + CS 模 256 自证 | 纯声明式 + L2(+0x33 混淆) |
| | IEC 60870-5-101 | FT1.2 定长帧 + 双写长度自证 | 纯声明式 + Checksum |
| | IEC 60870-5-104 | STARTDT/TESTFR/S/I 规范帧 | 纯声明式(位拆三态) |
| | HART | 命令 0 长帧 + XOR 自证 | 纯声明式 + Checksum |
| 车载 | SOME/IP | AUTOSAR 头示例 | 纯声明式(lengthAdjust) |
| | ISO-TP | SF/FF/FC/CF 向量 | 纯声明式(nibble 12bit 长度) |
| 网络 | ARP | who-has 权威向量 + gratuitous | 纯声明式(四地址 lengthField) |
| | ICMP echo | RFC 1071 反码和 0xFFFF 性质 | 纯声明式 + Checksum + @Payload |
| | DNS | 权威 A 查询向量 | 纯声明式(sentinel 标签列表) |
| | Ethernet▸IPv4▸UDP▸DNS | 全栈 75B 整帧 | 分派树 + StackEncoder 自动接线 |
| IoT/通用 | MQTT 3.1.1 | 规范 CONNECT 示例 | 纯声明式 + 内置 Varint |
| | MQTT-SN | SEARCHGW/CONNECT 双形态 | L2(0x01 长度转义) |
| | CoAP | 头部/options/payload 向量 + 13/14 逃逸 | L2(nibble delta) |
| | WebSocket | RFC 6455 §5.7 掩码向量 + 126 逃逸 | 纯声明式 + L2(掩码 XOR) |
| | QUIC varint | RFC 9000 §16 四向量 | L2(前缀定宽) |
| | BSON | 手导向量 {a:1}/{hello:"world"} | 纯声明式(全小端) |

**使用效果结论**:18 个协议族中 13 个纯声明式完成(72%),5 个借用 L2 逃生舱(变长整数/转义/混淆/掩码类,均在 20~40 行内解决);边界测试发现的 9 项缺陷修复后,真实协议建模无一处被引擎卡住。
