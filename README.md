# netproto — 注解驱动的自顶向下协议引擎

用**注解**定义任意复杂的二进制协议:条件解析、四种循环解析、变长、位级、异构 TLV 分派、计算字段,全部声明式;整条协议栈(Ethernet → IPv4 → UDP/TCP → 你的业务协议)本身就用同一套注解描述,运行时**自顶向下**分派——**只解析被 `@Protocol` 标记的协议**,其余流量保持原始字节。Spring Boot 自动装配、内置实时观测页面、原始以太网帧注入发包。

> 设计文档:`docs/superpowers/specs/2026-10-19-protocol-stack-redesign.md`(完整规范)
> 分支:`redesign/protocol-stack`

## 三分钟接入

```java
// 1. 定义协议:一个 POJO + 注解,无需手写任何序列化代码
@Protocol(id = "my-app", name = "My App Protocol")
@BindOn(parent = "udp", when = "dstPort == 9999 || srcPort == 9999")
@Data
public class MyProtocol {
    @ProtocolField(order = 1, size = 8)  private byte version = 1;
    @ProtocolField(order = 2, size = 8)  private byte type;
    @ProtocolField(order = 3, size = 16) private short reserved;
    @ProtocolField(order = 4, size = 32) private int sequenceId;
    @Payload                              private byte[] payloadData;
}
```

```bash
# 2. 启动(自动扫描 @Protocol 注册,内置协议栈恒可用)
./mvnw spring-boot:run
# 3. 打开 http://localhost:8080 —— 观测页面:实时帧表格 / 层级树 / 字段表 / hex 高亮 / 发包面板
```

线上出现 UDP 9999 的流量时,自动走完 `ethernet▸ipv4▸udp▸my-app` 四层解析;其它未注册协议的流量停在已注册层,payload 不做任何解析。

## 注解语言:六维度 + 三级逃生舱

任何二进制协议的复杂度 = 六个正交维度,注解覆盖常用形态,长尾走逃生舱:

| 维度 | 声明式写法 |
|---|---|
| 位级定长 | `@ProtocolField(order, size)` —— 4/6/13 bit,MSB 优先大端,跨字节 |
| 出现条件 | `presentIf = "ihl > 5"`(`== != < <= > >= && \|\| !` + 0x 字面量,只能引用先验字段) |
| 变长 | `lengthField + lengthUnit + lengthAdjust`(UDP「长度含自身」用负 adjust) |
| 循环·count | `type = LIST, elementClass = X.class, countField = "n"` |
| 循环·终止符 | `sentinel = 0x00`(byte[]/String/List 皆可,C 风格零终止字符串) |
| 循环·耗尽 | `untilEnd = true`(读到本层末尾;元素须自定边界) |
| 循环·异构分派 | `type = LIST_TLV, dispatch = {"1=SubnetMask","3=Router"}, tlvEndMarker = 255` |
| 元素内终止 | `sentinelOn + sentinelValue`(DNS 名标签) |
| 计算字段 | `@ChecksumField` + 实体实现 `Checksum`(编码置 0 → 序列化 → 回写) |
| 上下文钩子 | `DynamicSize`(尺寸)、`PayloadAware`(组装期长度) |
| 展示元数据 | `label`(Wireshark 式字段名)、`group`(命名组,观测页折叠;注册期校验相邻+字节对齐) |

**逃生舱**(覆盖"所有"协议的真正答案——加逃生舱,不加注解语法):

```java
// L2 字段级:一个字段太怪(varint/压缩指针/offset 定位),10 行代码接管它
public class VarintCodec implements FieldCodec<Long> { /* read/write/sizeOf */ }
@ProtocolField(order = 2, custom = VarintCodec.class) private Long uptimeMs;

// L3 报文级:整个协议手写(等价 pcap4j 能力,但可插回注解栈分派)
@Protocol(id = "quirky", codec = QuirkyHandCodec.class)
@BindOn(parent = "udp", when = "dstPort == 8888")
```

设计红线:动态维度只引用先验字段(单遍、注册期静态校验);条件是手写递归下降小语言(非 SpEL,确定性可 AOT);编解码对称(round-trip 是验收标准);注解无状态(IP/TCP 重组属帧后处理器,本期不做)。

## 自顶向下分派

内置协议栈(`protocol/builtin/`)与用户协议**同一套机制**:

```
@Protocol(id = "ipv4")  @BindOn(parent = "ethernet", when = "etherType == 0x0800")
@Protocol(id = "ipv6")  @BindOn(parent = "ethernet", when = "etherType == 0x86DD")
@Protocol(id = "udp")   @BindOn(parent = "ipv4",     when = "protocol == 17")
                         @BindOn(parent = "ipv6",    when = "nextHeader == 17")
@Protocol(id = "tcp")   @BindOn(parent = "ipv4",     when = "protocol == 6")
                         @BindOn(parent = "ipv6",    when = "nextHeader == 6")
@Protocol(id = "icmp")  @BindOn(parent = "ipv4",     when = "protocol == 1")
@Protocol(id = "arp")   @BindOn(parent = "ethernet", when = "etherType == 0x0806")
```

解码:解析 ethernet → 对已解析字段求值子绑定 → 命中 ipv4 → payload 继续下降……畸形层停止下降、无绑定停在当前层。**全程不使用 pcap4j 协议工厂**(`RawPacketListener` 只拿原始字节),这就是「只关注被标记的协议」的机制保证。

组装:`StackEncoder.encode([ethernet, ipv4, udp, app])` 自底向上,选择子字段(etherType/protocol/端口)按绑定 `when` **自动接线**(只填未设置的字段,显式值优先),`PayloadAware` 钩子自动填 totalLength/udp.length,校验和两遍式回写。

## Spring Boot 自动装配

```yaml
netproto:
  enabled: true          # 总开关
  base-packages: []      # 用户协议扫描包;默认主应用包(内置栈恒注册)
  root-protocol: ethernet
  ring-size: 100000      # 帧数上限(护列表规模);实际驻留由字节预算决定
  ring-bytes: 16MB       # 内存预算:超出按最旧淘汰(Wireshark 捕获缓冲同思路)
  snaplen: 65536
```

`NetprotoAutoConfiguration`(`AutoConfiguration.imports`)扫描 `@Protocol` → 构建分派树(重复 id / 未知父 / 非法 when → 启动失败)→ 装配 `StackDecoder` / `CaptureEngine` / `RawSender` / REST+SSE。入口类零手工注册。

## REST / SSE API

```
GET  /api/netproto/config            # 运行配置只读视图(前端显示参数以它为准)
GET  /api/netproto/protocols         # 注册协议 + 字段元数据(label/group/位标志)
GET  /api/netproto/interfaces         # 网卡列表
POST /api/netproto/capture/start      # {iface, bpf?}
POST /api/netproto/capture/stop
GET  /api/netproto/capture/status
GET  /api/netproto/packets?limit=     # 最近帧(结构化)
GET  /api/netproto/stream             # SSE 实时推送(事件名 packet)
POST /api/netproto/inject             # {hex} 注入原始帧,走完整解析管线(不经过网卡)
POST /api/netproto/send               # {iface, layers:[{protocol, fields}]} 原始以太网注入
GET  /api/netproto/export             # 环形缓冲导出 .pcap(Wireshark 可打开)
POST /api/netproto/import             # 导入 .pcap(multipart,仅以太网链路)
```

发包 JSON 便捷格式:`byte[]` 字段给 hex 字符串;`*Mac` 字段给 `"aa:bb:cc:dd:ee:ff"`;`*Ip` 字段给点分十进制;选择子与长度字段自动填写。

## 诚实边界

- Windows 采集/发包需要 **Npcap + 管理员权限**(libpcap 体系前提)。
- raw TCP 注入无内核栈握手,仅演示/测试用途;UDP/TCP 校验和发 0(伪头属跨层信息,UDP 下合法,TCP 下演示边界)。
- IP 分片重组、TCP 流重组是帧后处理器职责,本期未实现(`DecodedPacket` 消费者接口已预留)。
- IPv6 只实现固定基本头:扩展头链(Hop-by-Hop/路由/分片…)不在分派树内,nextHeader 为扩展头类型时解析停在 ipv6 层;ICMPv6 校验和需伪头(跨层),组装置 0。
- 发送帧不含 FCS(通常由驱动负责)。

## 测试

```bash
./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1
```

140 个测试,按模块分布:core 68(引擎+栈,内联夹具)/ protocols 44(含 pcap4j parity 对照:IPv4/IPv6/TCP)/ web 10(装配扫描+pcap+格式化)/ demo 18(真实协议 round-trip + 上下文 + REST 冒烟)。覆盖:位级/条件/变长/LIST/TLV/sentinel/校验和/parity + Expr 文法、四层分派、IPv6 双栈分派(udp/tcp/icmpv6)+ VLAN、未注册端口停止、畸形层停止、选择子自动接线、长度钩子、L2 varint、L3 手写 codec、注册校验、自动装配、REST,以及 Modbus/S7/DLT645/ISO8583/MQTT/Kafka 真实报文样例。

## 模块结构(按需引入)

```
netproto-parent
├── netproto-core          注解 + 反射编解码引擎 + Expr 小语言 + 分派栈(Registry/Decoder/Encoder)
│                          零依赖(仅 slf4j-api)—— 不依赖 Spring / pcap4j / Jackson
├── netproto-protocols     协议组包/扩展:内置栈(ethernet/arp/vlan/ipv4/ipv6/icmp/icmpv6/udp/tcp)
│                          + DNS/DHCP/IP/TCP 扩展定义(模块共 24 个 @Protocol),依赖 core
├── netproto-web   starter:自动装配(扫描 @Protocol)+ CaptureEngine + RawSender
│                          + REST/SSE + 内置观测页面;protocols 为 optional(可自带协议栈)
└── netproto-demo          演示/测试应用:全模块引入 + 真实协议套件(Modbus/S7/DLT645/
                           ISO8583/MQTT/Kafka)+ Spring Boot 入口
```

按需引入示例:只做协议编解码 → `netproto-core`;要标准协议栈 → 加 `netproto-protocols`;
要观测页面/采集/发包 → 加 `netproto-web`(不想用内置栈可 exclude `netproto-protocols`,
配 `netproto.builtin-packages: []` 并提供自己的根协议)。

## 目录结构

```
netproto-core/       com.netproto.{annotation,core,stack}
netproto-protocols/  com.netproto.protocols.{builtin,dns,dhcp,ip,eth,tcp}
netproto-web/        com.netproto.spring.{config,capture,web} + static 观测页(前端源码 ui/,Vite + TS)
netproto-demo/       com.netproto.demo(DemoApplication + protocol.realworld 真实协议套件)
```
