<div align="center">

# netproto

**注解驱动的自顶向下二进制协议引擎**

一个 POJO + 注解,描述任意二进制协议 —— 条件字段、变长、位级、四种循环、异质 TLV、
校验和、帧尾 CRC,全部声明式;`Ethernet → IPv4 → UDP/TCP → 你的业务协议`
整条栈用同一套机制自顶向下分派。

**只解析被 `@Protocol` 标记的协议,其余流量保持原始字节。**

[快速开始](#快速开始) · [核心概念](#核心概念) · [注解语言](#注解语言) · [观测台](#观测台) · [REST / SSE API](#rest--sse-api) · [诚实边界](#诚实边界)

</div>

---

## 为什么是「自顶向下」

Wireshark 式解析器通常靠大量手写 `if (type == X) parseX()` 串联,协议一多就变成一坨
不可维护的 switch;而 pcap4j 这类库把协议写死在类型体系里,新协议只能 fork。

netproto 把「下一层是谁」也变成声明:

```java
@Protocol(id = "udp")
@BindOn(parent = "ipv4", when = "protocol == 17")   // 父层字段满足条件时才下降
@BindOn(parent = "ipv6", when = "nextHeader == 17")
class UdpSegment { /* 字段 */ }

@Protocol(id = "my-app")
@BindOn(parent = "udp", when = "dstPort == 9999 || srcPort == 9999")
class MyProtocol { /* 字段 */ }
```

解码时引擎从根协议开始,解析一层 → 对已解析字段求值子绑定 → 命中则从头部之后继续下降;
没有绑定命中就停在当前层,剩余字节原样保留。**全程不经过任何协议工厂** —— 采集层只拿到
原始字节,「只关注被标记的协议」是机制保证,不是约定。

组装方向对称:`StackEncoder.encode([ethernet, ipv4, udp, app])` 自内向外逐层包装,
选择子字段(EtherType / IP protocol / 端口 / 你的类型字段)按绑定条件**自动接线**,
长度字段由 `PayloadAware` 钩子回填,校验和两遍式回写 —— 只给真正要填的值。

## 特性一览

- **声明式协议定义** —— 字段顺序、位宽、端序、变长、条件、循环、TLV 分派,全部注解表达,零手写序列化代码
- **自顶向下分派** —— `@BindOn(parent, when)` 声明父层条件,一条协议栈就是一个分派树;内置栈与业务协议同一套机制
- **只解析被标注的协议** —— 未命中的流量停在已注册层,不猜、不丢、不解析
- **编解码对称** —— round-trip 是验收标准;同一份注解同时驱动解析与组装
- **帧尾字段** —— `@Payload` 长度驱动 + 其后声明的尾随字段(帧尾 CRC / 结束符),专治「公共头 + 类型分派 + 帧尾校验」形态
- **三级逃生舱** —— L1 声明式动态(条件/长度/计数/终止符/分派)、L2 字段级 `FieldCodec`、L3 报文级 `PacketCodec`,长尾协议不用改引擎
- **Spring Boot 自动装配** —— 扫描 `@Protocol` 即注册,入口类零代码;配置失败启动即 fail-fast
- **内置观测台** —— 实时帧表格(10 万行虚拟滚动)、层级字段树、hex/ASCII 双视图选区、分层发包面板、pcap 导入导出
- **core 零第三方依赖** —— 仅 `slf4j-api`;不依赖 Spring / pcap4j / Jackson

## 快速开始

**要求**:JDK 25、Maven 3.9+;Windows 上采集/发包需安装 [Npcap](https://npcap.com/) 并以管理员身份运行。

```bash
# 构建全部模块(含测试)
mvn install

# 启动演示应用(内置三套业务协议 + 观测台),端口 8848
mvn -pl netproto-demo spring-boot:run
# 打开 http://localhost:8848
```

前端源码开发(热更新,`/api` 代理到 8848):

```bash
cd netproto-web/ui
npm install
npm run dev          # http://localhost:5173
npm run build        # 产物直接落进 netproto-web/src/main/resources/static,打 jar 即带页面
```

不想跑演示应用、只用自己的 Spring Boot 工程:

```xml
<dependency>
    <groupId>com.netproto</groupId>
    <artifactId>netproto-web</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

加上依赖、写好 `@Protocol` 类,启动即完成注册与装配。

## 三分钟接入

```java
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

线上出现 UDP 9999 的流量时,自动走完 `ethernet▸ipv4▸udp▸my-app` 四层解析;
其它未注册协议的流量停在已注册层,payload 不做任何解析。

已有 pcap 想验证?直接用观测台的 **导入 .pcap**(或 `POST /api/netproto/import`),
你也可以在测试里两行完成编解码:

```java
// 编码:POJO 列表(外层 → 内层)
byte[] frame = encoder.encode(List.of(ethernet, ipv4, udp, myProtocol));

// 解码:字节从根协议自顶向下分派,每层取回 POJO
DecodedPacket p = decoder.decode(frame, "udp", 0, 1);
MyProtocol msg = (MyProtocol) p.layers().get(3).packet();
```

> 完整用法文档见 `netproto-demo/src/test/java/.../powerdist/PowerDistProtocolTest.java`
> —— 五个用例分别演示:编码到逐字节期望值、手拼 hex 解码、往返无损、整栈分派、计数驱动变长列表。

## 核心概念

| 概念 | 说明 |
|---|---|
| `@Protocol(id)` | 协议节点。`id` 是分派树节点名,全局唯一;`internal = true` 标记公共头等中间产物(不占侧栏/不参与过滤/不进发包目标,解码树照常展示) |
| `@BindOn(parent, when)` | 挂到父层节点,`when` 是父层字段上的条件表达式;可重复声明(如 tcp 同时挂 ipv4 与 ipv6) |
| `@ProtocolField(order, ...)` | 一个字段。`order` 决定线序,其余属性按需 |
| `@Payload` | 载荷字段。裸用 = 吃掉本层剩余字节;配合 `@ProtocolField(lengthField, lengthAdjust)` = 长度驱动,其后可声明尾随字段 |
| `@ChecksumField` | 计算字段。编码期置 0 → 序列化 → 调实体 `compute()` → 回写 |
| 自定界 | 变长字段必须知道自己何时结束(长度/计数/终止符),否则其后再有字段会错位 |

**设计红线**:动态维度只引用先验字段(单遍解码,注册期静态校验);条件谓词是手写递归下降小语言
(非 SpEL,确定性、无反射调用);注解描述无状态结构,会话/重组属帧后处理器。

## 注解语言

任何二进制协议的复杂度可拆成六个正交维度 —— 注解覆盖常用形态,长尾交给逃生舱。

| 维度 | 声明式写法 |
|---|---|
| 位级定长 | `@ProtocolField(order, size)` —— 4/6/13 bit,MSB 优先大端,可跨字节 |
| 出现条件 | `presentIf = "ihl > 5"`(`== != < <= > >= && \|\| !` + 0x 字面量) |
| 变长 | `lengthField + lengthUnit + lengthAdjust`(UDP「长度含自身」用负 adjust) |
| 循环 · 计数 | `type = LIST, elementClass = X.class, countField = "n"` |
| 循环 · 终止符 | `sentinel = 0x00`(byte[]/String/List 皆可,C 风格零终止) |
| 循环 · 耗尽 | `untilEnd = true`(读到本层末尾;元素须自定边界) |
| 循环 · 异构 TLV | `type = LIST_TLV, dispatch = {"1=SubnetMask","3=Router"}, tlvEndMarker = 255` |
| 元素内终止 | `sentinelOn + sentinelValue`(DNS 名标签) |
| 计算字段 | `@ChecksumField` + 实体实现 `Checksum` |
| 上下文钩子 | `DynamicSize`(尺寸)、`PayloadAware`(组装期长度回填) |
| 枚举 / 位标志 | `enumClass`(语义数字)、`flagClass`(逐位展开为 `Set<枚举>`) |
| 展示元数据 | `label`(Wireshark 式字段名)、`group`(观测页命名组,逐级分组) |

### 帧尾字段:公共头 + 类型分派 + 帧尾 CRC

工控/电力/串口协议最常见的形态 —— 头、分派、尾部校验 —— 现在可以一套注解写到底:

```java
@Protocol(id = "pd")
@BindOn(parent = "udp", when = "dstPort == 9000")
@Data
public class PdFrame implements PayloadAware {

    @ProtocolField(order = 1, size = 8)  private int version = 0x21;
    @ProtocolField(order = 2, size = 8)  private int signalType;   // 分派选择子(自动接线)
    @ProtocolField(order = 3, size = 16) private int frameLength;  // 整帧长度(自动回填)
    @ProtocolField(order = 4, size = 32) private int srcAddr;

    /** 长度驱动载荷:body = frameLength - 头 - 尾;其后仍可声明字段 */
    @Payload
    @ProtocolField(order = 5, lengthField = "frameLength", lengthAdjust = -6)
    private byte[] body = new byte[0];

    /** 帧尾 CRC:覆盖头+体,编码期置 0 → 序列化 → 计算 → 回写 */
    @ProtocolField(order = 6, size = 16)
    @ChecksumField
    private int crc;

    @Override public void onPayload(byte[] inner) { this.frameLength = 6 + inner.length; }
}
```

解码时 body 按长度截断、CRC 照常读出,**子协议分派入口停在 body 起点**(不被尾随字段吃掉);
编码期校验长度字段与实际 payload 一致,不符立即报错而不是产出错帧。

> 注意区分两种模式:**自包含帧**(无子协议)可用任意自定界方式;只有长度驱动的 `@Payload`
> 才能在 body 后跟字段。裸 `@Payload`(取剩余字节)在结构上只能是线路最后一个字段 ——
> 若在其后声明 CRC,该字段会按普通前序字段读取,位置错位且注册期不会报错。

### 中间产物:`internal`

公共头是结构层、不是端到端业务。标记 `internal = true` 后:

```java
@Protocol(id = "pd", name = "智能配电接入", internal = true)
```

- 不进观测台侧栏过滤列表、不参与过滤命中
- 不进发包目标选择(信令体仍可选)
- 解码树的层级与字段、hex 高亮照常展示

### 逃生舱:加逃生舱,不加注解语法

L1 是上面那些声明式动态属性(条件 / 长度 / 计数 / 终止符 / TLV 分派);仍然覆盖不到的,
用 L2 / L3 接管,而不是继续往注解里堆语法:

```java
// L2 · 字段级:一个字段太怪(varint / 压缩指针 / offset 定位),十行代码接管它
public class VarintCodec implements FieldCodec<Long> {
    public Long read(BitCursor c, FieldContext ctx, int remaining) { /* ... */ }
    public void write(BitCursor c, FieldContext ctx, Long v) { /* ... */ }
    public long sizeOf(Long v) { /* ... */ }
}
@ProtocolField(order = 2, custom = VarintCodec.class) private Long uptimeMs;

// L3 · 报文级:整个协议手写(等价 pcap4j 能力),但仍通过 @BindOn 插回分派树
@Protocol(id = "quirky", codec = QuirkyHandCodec.class)
@BindOn(parent = "udp", when = "dstPort == 8888")
```

自定义实现必须有无参构造、在 codec 构建期实例化并复用(须无状态或线程安全);
`FieldCodec` 拿得到已解析字段的只读视图,可以做依赖先验字段的动态解析。

## 内置协议栈

`com.netproto.protocols.builtin`,与业务协议同一套机制,可整体替换:

| 协议 | 挂载条件 |
|---|---|
| `ethernet` | 根协议(可配 `root-protocol`) |
| `vlan` | `etherType == 0x8100` |
| `arp` | `etherType == 0x0806` |
| `ipv4` | `etherType == 0x0800` |
| `ipv6` | `etherType == 0x86DD` |
| `icmp` | `protocol == 1` |
| `tcp` | `protocol == 6` / `nextHeader == 6` |
| `udp` | `protocol == 17` / `nextHeader == 17` |
| `icmpv6` | `nextHeader == 58` |

不想用内置栈:`netproto.builtin-packages: []`,并提供自己的根协议。

## Spring Boot 自动装配

```yaml
netproto:
  enabled: true              # 总开关
  base-packages: []          # 用户协议扫描包;留空 = 自动探测 @SpringBootApplication 所在包
  builtin-packages:          # 内置栈扫描包(设 [] 可禁用)
    - com.netproto.protocols.builtin
  root-protocol: ethernet    # 分派树根
  ring-size: 100000          # 环形缓冲帧数上限
  ring-bytes: 16MB           # 内存预算:超出按最旧淘汰(与帧数上限取先到者)
  snaplen: 65536
```

`NetprotoAutoConfiguration` 扫描 `@Protocol` → 构建分派树 → 装配 `StackDecoder` /
`StackEncoder` / `CaptureEngine` / `RawSender` / REST + SSE。重复 id、未知父、非法条件表达式
都会让应用**启动失败**——宁可起不来,也不要线上静默解析错。

不用 Spring 时,core 是纯库:

```java
ProtocolRegistry registry = ProtocolRegistry.create(
        EthernetFrame.class, Ipv4Packet.class, UdpSegment.class, PdFrame.class, PdRegister.class);
registry.validateBindings();
StackDecoder decoder = new StackDecoder(registry, "ethernet");
StackEncoder encoder = new StackEncoder(registry);
```

## 观测台

`http://localhost:8848`(或前端 dev `:5173`),一页完成 采集 → 观察 → 构造 → 回放:

- **帧表格** —— 虚拟滚动(缓冲上限 10 万行)、列宽可拖拽并持久化、单行省略、选中行高亮
- **协议侧栏** —— 多级分组(系统 → 子组 → 协议,深度不限)、三态勾选、每级实时命中计数;`internal` 公共头不占位
- **详情面板** —— 层级字段树(Wireshark 式位级展示、位标志逐位展开、命名组折叠)、hex 与 ASCII 双视图、
  选中字段的阶梯形描边外框(跨行连成一个整体,水平不相交时自动拆分)、字节 ↔ 树双向联动
- **发包面板** —— 选目标协议自动推导整条协议链;分层表单带格式徽标(`dec·2B` / `hex` / `MAC·6B` / `IP·4B` / `flags`)、
  位标志多选、条件字段实时显隐、`自动` 字段留空即可;填写值按协议链缓存;JSON 高级模式随时切换
- **pcap 导入 / 导出** —— 导出的 `.pcap` Wireshark 可直接打开;导入替换当前列表用于离线分析

## REST / SSE API

```
GET  /api/netproto/config             # 运行配置只读视图
GET  /api/netproto/protocols          # 注册协议 + 字段元数据(id/name/groupPath/category/fields)
GET  /api/netproto/template?path=     # 按分派树推导协议链,生成发包模板
GET  /api/netproto/interfaces         # 网卡列表
POST /api/netproto/capture/start      # {iface, bpf?}
POST /api/netproto/capture/stop
GET  /api/netproto/capture/status
GET  /api/netproto/packets?limit=     # 最近帧摘要(结构化)
GET  /api/netproto/packet/{seq}       # 单帧完整详情(按需重解码)
GET  /api/netproto/stream             # SSE 实时推送(事件名 packet / ping)
POST /api/netproto/inject             # {hex} 注入原始帧,走完整解析管线(不经过网卡)
POST /api/netproto/send               # {iface, layers:[{protocol, fields}]} 原始以太网注入
GET  /api/netproto/export             # 环形缓冲导出 .pcap
POST /api/netproto/import             # 导入 .pcap(multipart,仅以太网链路)
```

发包 JSON 的便捷格式:`byte[]` 字段给 hex 字符串;`*Mac` 字段给 `"aa:bb:cc:dd:ee:ff"`;
`*Ip` 字段给点分十进制;选择子与长度字段自动填写,显式值优先。

## 把引擎用在后端(而非抓包)

core 的编解码入口只认字节数组,数据来自网卡、socket 还是文件与它无关:

```java
// 收到一批字节 → POJO
PdFrame msg = (PdFrame) registry.get("pd").codec().decode(buf, 0, buf.length);

// 回包:POJO → 字节
byte[] out = encoder.encode(List.of(responseHeader, responsePdu));
```

需要清楚的边界:

- **一个数据报 / 一条完整消息的字节**才归它管。TCP 粘包/拆包必须在前面做组帧(长度字段、
  定界符或 Netty 的 `LengthBasedFrameDecoder`),切出完整报文再喂给 codec;UDP 天然定界,可直接解。
- **协议无状态**。会话序号校验、握手状态机、重传逻辑属于业务层。
- 反射式编解码适合业务协议量级(每秒数千~数万条),不适合做百万 PPS 的转发面。
- 解码失败会优雅停止(异常被捕获、停在当前层),但面向公网端口前请自行补齐输入上限与越界防护。

## 演示应用

`netproto-demo` 用三套真实形态的协议演示引擎能力(共 47 个 `@Protocol` 类):

| 系统 | 端口 | 结构 |
|---|---|---|
| 智能配电接入 | UDP 9000 | 16B 公共头 + 16 个信令体按 `signalType` 分派 + 计数驱动列表 |
| 设备通信 | UDP 9001 | 6B 设备编号 + 信令类型分派 + 12 个信令(接入管理 / 呼叫控制)+ 帧头定界条目 |
| 物联网(水利设备) | UDP 9002 | 16B 公共头 + 帧类型分派 + 计数列表 + 尾随保留/CRC |

三套协议端口隔离并存,同一注册表互不串扰。执行 `curl -X POST http://localhost:8848/api/demo/samples`
可一键注入「注册 → 许可 → 上报 → 参数响应」四帧交互样例,页面即时看到解析效果。

协议原始定义见 `netproto-demo/src/main/resources/powerdist-protocol.xml`。

## 测试

```bash
mvn test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1
```

当前 **152 个测试**:

| 模块 | 数量 | 覆盖 |
|---|---|---|
| core | 117 | 引擎 + 栈 + 内置协议栈 + 特性试金石(含 pcap4j parity 对照:IPv4/IPv6/TCP) |
| web | 12 | 自动装配扫描、pcap 读写、多会话隔离/上限、摘要格式化 |
| demo | 23 | 三套协议并存分派、编码/解码演示、帧尾 CRC 边界、REST 冒烟 |

覆盖范围:位级 / 条件 / 变长 / LIST / TLV / sentinel / 校验和 / parity 对照、Expr 文法、
四层分派、IPv6 双栈、VLAN、未注册端口停止、畸形层停止、选择子自动接线、长度钩子、
`@Payload` 尾随字段、L2 自定义字段 codec、L3 手写报文 codec、注册期校验、自动装配、REST。

## 模块结构

```
netproto-parent
├── netproto-core     注解 + 反射编解码引擎 + Expr 小语言 + 分派栈(Registry/Decoder/Encoder)
│                     + 内置协议栈 com.netproto.protocols.builtin
│                     零第三方依赖(仅 slf4j-api)—— 不依赖 Spring / pcap4j / Jackson
├── netproto-web      Spring Boot starter:自动装配(扫描 @Protocol)+ CaptureEngine + RawSender
│                     + REST/SSE + 内置观测页面(Vue 3 + Vite + naive-ui)
└── netproto-demo     演示应用:三套业务协议 + 样本注入 + Spring Boot 入口
```

按需引入:只做协议编解码 → `netproto-core`;要观测页面 / 采集 / 发包 → 加 `netproto-web`。

> `main` 分支只保留库模块(core / web),演示应用在 `redesign/protocol-stack` 分支维护。

```
netproto-core/       com.netproto.{annotation,core,stack,protocols.{builtin,tcp}}
netproto-web/        com.netproto.spring.{config,capture,web} + static 观测页(前端源码 ui/)
netproto-demo/       com.netproto.demo(DemoApplication + protocol.{powerdist,devcomm,iot})
```

## 诚实边界

- Windows 采集/发包需要 **Npcap + 管理员权限**;Wi-Fi 网卡通常拒绝原始帧注入,建议有线网卡。
- 原始帧注入无内核栈握手;UDP 校验和发 0(IPv4 下合法),TCP 校验和不含伪首部(演示边界)。
- 发送帧不含 FCS(通常由驱动负责)。
- **IP 分片重组、TCP 流重组未实现** —— 属帧后处理器职责,`DecodedPacket` 消费接口已预留。
- IPv6 只实现固定基本头:扩展头链(Hop-by-Hop / 路由 / 分片)不在分派树内,`nextHeader` 为扩展头时解析停在 ipv6 层。
- 变长字段必须自定界;裸 `@Payload` 取本层剩余全部字节,因此线路上的尾随字段必须改用
  长度驱动的 `@Payload`(见上文「帧尾字段」)。
- 本机采集通常看不到自己注入的帧(取决于驱动/平台);要验证「发出去的东西」请在链路上抓。

## 设计文档

- 完整规范:`docs/superpowers/specs/2026-10-19-protocol-stack-redesign.md`
- 引擎演进记录(位字段 → 变长 → TLV → 枚举 → 校验和 → 尾随字段):`docs/superpowers/`
