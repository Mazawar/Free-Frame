# 协议栈重设计:注解驱动的自顶向下协议引擎(2026-10-19)

分支:`redesign/protocol-stack`(自 main)

## 0. 背景与问题

旧设计(9 个 phase 的 Free-Frame)把反射编解码引擎打磨得很扎实,但外围架构有五个结构性缺陷:

| # | 旧设计问题 | 后果 |
|---|---|---|
| 1 | `@ProtocolPacket(port=…)` 只能按 UDP/TCP 端口注册 | 协议无法挂在 ARP/ICMP/EtherType 上,无法描述"以太网→IP→传输层→应用"的层级关系 |
| 2 | 解析路径硬编码在 `PcapService.parsePacket` | 先用 pcap4j 工厂解析全世界所有协议,再在字符串层面"补救",违背"只关注被标记的协议" |
| 3 | 解析结果存 `List<String>` | 无结构化数据,无法做层级树/字段表/hex 定位 |
| 4 | 无发包能力 | 只能看不能发 |
| 5 | 注册靠 `main()` 手动调 `ProtocolRegistry.register` | 无 Spring 自动装配,协议一多就是维护灾难 |

**保留资产**:反射编解码引擎(`ProtocolCodec`/`BitCursor`/`FieldContext`/注解/校验和回写/两遍式序列化)及其全部测试——这是六个复杂度维度里五个半的实现,重设计只补缺口、换外围。

## 1. 目标与非目标

### 目标
1. **注解描述复杂协议**:条件解析、循环解析(四种驱动)、变长、位级、异构分派、计算字段,全部声明式。
2. **编解码可被重写**:字段级 `FieldCodec` SPI + 报文级 `PacketCodec` SPI,两级逃生舱。
3. **自顶向下分派**:整条协议栈(Ethernet→IPv4→UDP/TCP/ICMP→应用)本身就用注解定义,运行时按 `@BindOn` 规则逐层下降。
4. **只关注被标记的协议**:引擎只解析注册过的协议;未注册协议的 payload 保持原始字节。不使用 pcap4j 的协议工厂。
5. **Spring Boot 自动装配**:classpath 扫描 `@Protocol` 自动注册 + 启动期校验,零手工注册。
6. **内置页面**:SSE 实时推送结构化解析结果(层级树/字段表/hex 高亮),含发包面板。
7. **原始以太网发包**:pcap4j `sendPacket` 注入 L2 帧,组装时自动接线选择子字段(EtherType/protocol/端口)。

### 非目标(诚实边界)
- IP 分片重组、TCP 流重组:属"解析后处理器"层,本期不做(接口预留 `DecodedPacket` 消费者)。
- UDP/TCP 校验和的跨层伪头:UDP 发 0(合法"未计算");TCP 发 0 仅限演示(真实 TCP 需要内核栈握手,raw 注入本身就是 fire-and-forget)。
- Windows 发包需要 Npcap + 管理员权限;采集同理。这是 libpcap 体系的前提,不是本组件缺陷。
- 帧尾 FCS:发送时不生成(网卡/驱动通常负责)。

## 2. 核心设计思想:六维度 + 三级逃生舱

**任何二进制协议的字段级复杂性 = 六个正交维度**(出现条件/长度/重复/元素异构/计算字段/上下文依赖)。
注解只描述这六个维度;覆盖不到的长尾用三级逃生舱,而不是加注解语法:

```
L0 固定字段            @ProtocolField(order, size)
L1 声明式动态          presentIf / lengthField / countField / sentinel / untilEnd / dispatch / tlvEndMarker
L2 字段级逃生舱        @ProtocolField(custom = XFieldCodec.class)   —— 一个字段,10 行代码接管
L3 报文级逃生舱        @Protocol(codec = XPacketCodec.class)        —— 整个协议手写,仍挂回注解栈
L4 帧后处理器          ip 重组/tcp 重组等跨帧状态(本期不做)
```

**四条设计红线**:
1. 动态维度只能引用 order 更小的字段(先验引用),注册期静态校验 → 单遍解析、无循环依赖。
2. 条件表达式是手写递归下降的纯小语言(`== != < <= > >= && || ! ( )` + 十进制/0x 字面量),不是 SpEL:确定性、可 AOT、无注入面。
3. 编解码对称:一切特性必须过 round-trip 测试。
4. 注解无状态:跨帧/会话状态一律推到 L4。

## 3. 注解语言规范

### 3.1 `@Protocol`(类级,替代旧 `@ProtocolPacket`)

```java
@Protocol(
    id      = "my-app",              // 必填,全局唯一,分派树节点名
    name    = "My App Protocol",     // 显示名,默认取 id
    builtin = false,                 // 内置协议标记(UI 徽标;不影响语义)
    codec   = void.class             // L3 逃生舱:整个报文的编解码器,默认反射式
)
```

- 不带 `@BindOn` 的 `@Protocol` 是"孤岛协议":不参与分派树,但仍可作 NESTED/LIST 元素、可被 `StackEncoder` 直接编码。
- `codec` 指向的类必须实现 `PacketCodec<T>` 且有无参构造。

### 3.2 `@BindOn`(类级,可重复,声明父协议与命中条件)

```java
@BindOn(parent = "udp", when = "dstPort == 9999 || srcPort == 9999", priority = 0)
```

- `parent`:父协议 id。根协议(默认 `ethernet`)无需 `@BindOn`。
- `when`:命中条件表达式,标识符必须是父协议的 `@ProtocolField` 字段名。父字段未解析(条件字段缺席)时按 false 处理,不抛异常。
- `priority`:同父多绑定命中时取高者;平级取注册顺序(启动告警)。
- 可重复:同一协议可挂多个父(如同时挂 ipv4/ipv6)。

### 3.3 `@ProtocolField`(字段级,新增两个属性)

完整属性表(★=本次新增):

| 属性 | 语义 | 所属维度 |
|---|---|---|
| `order` | 排列顺序(必填) | — |
| `size` | 位宽(任意正整数,不要求 8 的倍数) | 长度 |
| `type` | INT/UNSIGNED/BYTES/STRING/NESTED/LIST/LIST_TLV | — |
| `lengthField`+`lengthUnit`+`lengthAdjust` | 变长:引用先验字段值 ± 偏移(UDP"长度含自身"用负 adjust 校正) | 长度 |
| `presentIf` | 出现条件表达式(L1 小语言) | 出现条件 |
| `countField` | LIST 元素个数引用先验字段 | 重复 |
| `elementClass` | LIST/LIST_TLV 元素类型(必须是 `@Protocol` 类) | 重复 |
| `sentinel` | 终止符字节(0x00–0xFF),读到即停 | 重复 |
| `sentinelOn`+`sentinelValue` | 元素内字段终止判定(DNS 名) | 重复 |
| `tlvEndMarker`+`dispatch` | 异质 TLV:type→实体类分派表 + 结束 type | 重复+异构 |
| ★`untilEnd` | LIST 读到缓冲区耗尽为止(元素须自定边界) | 重复 |
| ★`custom` | L2 逃生舱:`FieldCodec` 实现,接管该字段读写 | 全部 |
| `charset`/`enumClass`/`flagClass` | 字符集/枚举/位标志 | — |

互斥校验(注册期):`sentinel`×`countField`×`lengthField`×`untilEnd` 四者互斥;`custom` 与 `lengthField`/`size` 互斥(尺寸由 `sizeOf` 决定)。

### 3.4 条件表达式小语言(Expr)

```
or   := and ('||' and)*
and  := not ('&&' not)*
not  := '!' not | cmp
cmp  := primary (('=='|'!='|'<'|'<='|'>'|'>=') primary)?
primary := '(' or ')' | ident | int-literal(十进制|0xHH)
```
- 标识符解析:先验字段值(`Number.longValue()`)。
- 两种模式:`presentIf` 严格模式(未知标识符抛异常,注册期已校验存在);`when` 宽松模式(未解析字段→整个表达式 false)。
- `@Payload` 尾部字段:吃剩余字节(现状保留)。

## 4. 引擎内部设计

### 4.1 SPI 契约

```java
public interface PacketCodec<T> {
    T decode(byte[] data, int offset, int length);      // 解析
    byte[] encode(T packet);                             // 组装(两遍式+校验和回写)
    int headerBytes();                                   // 最近一次 decode 的头部消费字节数(payload 之前);-1=不支持子层分派
}

public interface FieldCodec<T> {                         // L2 逃生舱
    T read(BitCursor cursor, FieldContext ctx, int remainingBytes);
    void write(BitCursor cursor, FieldContext ctx, T value);
    long sizeOf(T value);                                // 序列化前置尺寸(两遍式第一遍用)
}

public interface PayloadAware {                          // 组装期钩子:内层字节就绪后调整自身长度字段
    void onPayload(byte[] innerPayload);
}
```

`ProtocolCodec<T>`(反射式默认实现)实现 `PacketCodec`;`headerBytes()` 返回固定字段消费的位宽取整字节。

### 4.2 自顶向下解码(StackDecoder)

```
decode(frame):
  layers = []; id = root("ethernet"); off = 0
  while id != null && off < frame.len:
      entry = registry[id]
      obj   = entry.codec.decode(frame, off, frame.len - off)   // 失败→该层记为 raw,停止下降
      hdr   = entry.codec.headerBytes() (<=0 → 不再下降)
      layers += Layer(id, obj, off, hdr)
      childOff = off + hdr
      child  = registry.matchChild(id, obj)                      // 按优先级求值 @BindOn.when
      if child == null || childOff >= frame.len: break           // 无子协议:payload 保持原始
      id = child; off = childOff
```

`matchChild`:对父对象的 `@ProtocolField` 字段构建 `FieldContext`,逐绑定求值 `when`(宽松模式)。

### 4.3 自底向上组装(StackEncoder)+ 选择子自动接线

```
encode([eth, ip, udp, app]):
  bytes = codec(app).encode(app)                    // 最内层先编码
  for i 从倒数第二层到第一层:
      set @Payload field(layer_i, bytes)            // 注入内层字节
      if layer instanceof PayloadAware p: p.onPayload(bytes)   // totalLength/udpLength 等
      autoWire(layer_i, layer_{i+1}.id)             // ★从子绑定的 when 提取 "field == literal" 赋值
                                                     //  etherType=0x0800 / protocol=17 / dstPort=9999
      bytes = codec(layer_i).encode(layer_i)
```
`autoWire` 规则:取 `when` 第一个 `||` 子句中所有 `ident == literal` 合取项反射赋值;表达式含 `!=`/`<`/`!` 时跳过并告警(需手工设置)。编码仍走两遍式 + `Checksum` 回写。

### 4.4 协议注册表(ProtocolRegistry 重写)

- `Map<String, Entry>`:id → {meta, PacketCodec, type}。重复 id 启动失败。
- `Map<String, List<Binding>>`:parent → 绑定列表(priority 降序)。
- 注册期校验:id 唯一;`@BindOn.parent` 存在;`when` 标识符是父类 `@ProtocolField` 字段;字段级互斥规则(3.3)。
- 实例化(不再静态单例,Spring bean);`ProtocolRegistry.create(Class<?>...)` 供测试。

### 4.5 内置协议栈(builtin 包,与用户协议同机制)

| id | 绑定 | 关键字段/钩子 |
|---|---|---|
| `ethernet` | 根 | dstMac48/srcMac48/etherType16 + @Payload |
| `arp` | eth `etherType==0x0806` | 固定 28B,无 payload |
| `ipv4` | eth `etherType==0x0800` | version/ihl/…/protocol + @ChecksumField;`PayloadAware`(totalLength=20+payload);checksum=头 20B 反码和 |
| `icmp` | ip `protocol==1` | echo 头;checksum 全报文反码和 |
| `udp` | ip `protocol==17` | 端口/length;`PayloadAware`(length=8+payload);checksum 置 0(伪头边界) |
| `tcp` | ip `protocol==6` | 端口/seq/ack/flags(Set+TcpFlag);checksum 置 0(边界) |

内置包永远注册(硬编码扫描 `com.example.demo.protocol.builtin`),与用户 `base-packages` 并集;id 冲突启动失败。

## 5. Spring Boot 自动装配

```
netproto.enabled=true            # 总开关(matchIfMissing)
netproto.base-packages=          # 用户协议扫描包;默认 AutoConfigurationPackages(主应用包)
netproto.root-protocol=ethernet  # 分派树根
netproto.ring-size=500           # 环形缓冲容量
netproto.snaplen=65536
```

`NetprotoAutoConfiguration`(`META-INF/spring/...AutoConfiguration.imports`):
1. 扫描 builtin 包 + base-packages 中所有 `@Protocol` 类 → 构建 `ProtocolRegistry`(失败 fail-fast,带可读错误)。
2. 装配 `StackDecoder`/`CaptureEngine`/`RawSender`/`NetprotoController`(控制器经 bean 注册,由 `RequestMappingHandlerMapping` 正常识别)。
3. `DemoApplication.main` 不再出现任何手工注册。

## 6. 采集 / 发包 / Web

### CaptureEngine
- `start(iface, bpf?)`:openLive(snaplen, PROMISCUOUS) → 可选 setFilter(bpf) → loop;**不使用 pcap4j 协议工厂**,listener 只取 `getRawData()` 交给 `StackDecoder`。
- 结果 `DecodedPacket{ts, iface, layers[{id, obj, offset, headerLen}], raw}` → 有界环形缓冲 + `CopyOnWriteArrayList<Consumer>` 订阅者(SSE)。
- `stop/status/recent(limit)`。

### RawSender
- `send(iface, List<Object> layers)`:`StackEncoder.encode` → `handle.sendPacket(bytes)`(原始 L2 注入)。
- `send(iface, byte[] rawFrame)`:直接注入。
- 边界:Npcap+管理员;TCP 无握手。

### Web API + 内置页面
```
GET  /api/netproto/protocols        # 注册协议+字段元数据(供 UI 过滤器/表单)
GET  /api/netproto/interfaces       # 网卡列表
POST /api/netproto/capture/start    # {iface, bpf?}
POST /api/netproto/capture/stop
GET  /api/netproto/capture/status
GET  /api/netproto/packets?limit=   # 最近报文(结构化 JSON)
GET  /api/netproto/stream           # SSE 实时推送
POST /api/netproto/send             # {iface, layers:[{protocol, fields{…}}]} → Jackson 绑定 POJO → 组装注入
页面 /index.html                     # 无构建链,vanilla JS
```

页面布局:顶栏(网卡/BPF/启停/状态)| 左栏(协议过滤器,builtin 徽标)| 主区(实时表格:时间/五元组/协议路径/长度,点击看详情:层级手风琴+字段表+按层高亮的 hex dump)| 发包面板(JSON 层级模板 + 发送)。
SSE 断线自动重连;前端按勾选协议过滤展示。

层→JSON 视图约定:byte[]→hex;`*Mac`→`aa:bb:…`;`*Ip`→点分;enum/flag→名;LIST→递归数组。

## 7. 迁移清单

| 动作 | 对象 |
|---|---|
| 删除 | `@ProtocolPacket`、`@ProtocolTransport`、旧 `ProtocolRegistry`(静态端口表)、`PcapService`、`PcapController`、`DemoApplication` 手工注册 |
| 迁移 | `protocol/` 根下全部样例类 `@ProtocolPacket(port=N)` → `@Protocol(id="…")`(保留为 codec 测试夹具,不挂 BindOn) |
| 保留 | `ProtocolField/Payload/ChecksumField` 注解;`core/` 引擎全家;全部 codec 单测 |
| 新增 | 本文档涉及的 ~30 个新类 + 静态页面 |

## 8. 测试矩阵

旧:全部 codec 单测必须保持绿(允许因注解迁移/异常文案调整做等价修改)。
新:
1. `ExprTest`:文法全覆盖(运算符/括号/0x/一元!/未知标识符严格 vs 宽松)。
2. `StackDispatchTest`:eth(ip(udp(myapp))) 全链;arp 命中;未注册端口停在 udp;畸形 ip 层停止下降;root 缺失。
3. `CustomFieldCodecTest`(L2):varint 字段 round-trip + 尺寸。
4. `PacketCodecOverrideTest`(L3):手写 codec 被注册表优先。
5. `StackEncoderTest`:四层组装,自动接线 etherType/protocol/port,长度字段(PayloadAware)正确,decode round-trip 字段相等。
6. `RegistryValidationTest`:重复 id/未知父/未知 when 标识符/互斥规则。
7. `AutoConfigTest`:ApplicationContextRunner 验证扫描注册(不触网卡)。

命令约定:`./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`,合并前全量绿。

## 9. 模块化(2026-10-19 追加)

单模块重组为多模块 Maven 工程,按需引入:

| 模块 | 内容 | 依赖 |
|---|---|---|
| `netproto-core` | 注解 + 反射引擎 + Expr + 分派栈(Registry/Decoder/Encoder/DecodedPacket)+ VarintCodec | 仅 slf4j-api |
| `netproto-protocols` | 内置栈(builtin)+ DNS/DHCP/IP/eth/tcp 协议定义(组包/扩展) | core |
| `netproto-spring-boot` | 自动装配 + CaptureEngine + RawSender + REST/SSE + 观测页 | core + protocols(optional,可自带协议栈) |
| `netproto-demo` | Spring Boot 演示应用 + my-app/heartbeat 业务协议 | spring-boot + protocols |

要点:
- **core 零框架依赖**:不依赖 Spring/pcap4j/Jackson;原 ProtocolCodec 的 pcap4j 适配器(toPacket/AutoPacket)删除,采集只在 spring-boot 模块用 pcap4j。
- **内置栈可选**:`netproto.builtin-packages` 属性(默认 protocols 模块的 builtin 包),未引入模块时扫描降级为空;设空列表 + 自定义 root-protocol 可完全自带协议栈。
- **测试随夹具分布**:引擎内联夹具测试留 core(56);pcap4j parity/DNS/DHCP 夹具测试随协议定义进 protocols(38);装配测试进 spring-boot(2);应用/REST 冒烟进 demo(6)。栈引擎测试改用 core 内联迷你栈(mini-eth/ip/udp),不再依赖 protocols。
- 顺带加固:引擎 `newInstance` 补 `setAccessible(true)`(支持包私有协议类)。
- 包名体系:`com.example.netproto.{annotation,core,stack}` / `com.example.netproto.protocols.*` / `com.example.netproto.spring.*` / `com.example.demo`。

## 10. 实施顺序

1. 注解层(Protocol/BindOn/ProtocolField 扩展)
2. SPI(PacketCodec/FieldCodec)+ Expr
3. ProtocolCodec 改造(implements SPI/custom/untilEnd/Expr 统一)
4. Registry 重写 + StackDecoder/StackEncoder/PayloadAware + DecodedPacket
5. builtin 栈六类 + 样例迁移 + Heartbeat(L2 示例)
6. CaptureEngine + RawSender
7. 自动装配 + properties + imports
8. Web API + SSE + 页面
9. 测试修复 + 新增 → 全量绿
10. README 重写
