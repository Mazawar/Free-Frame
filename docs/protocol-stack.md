# 协议栈:自顶向下分派与自动组装

## 1. 分派树

协议之间的层级关系全部由 `@BindOn` 声明,启动时构建成一棵树:

```
ethernet ─┬─ vlan ─┬─ ipv4 ─┬─ udp ─┬─ 智能配电(pd, 9000 端口)
          │        │        │       └─ 设备通信(devcomm, 9001)
          ├─ ipv4 ─┤        ├─ tcp ─── 物联网水利(iot, 9002)
          ├─ ipv6 ─┴─ icmp
          └─ arp
```

- 不带 `@BindOn` 的是**孤岛协议**(串口/裸流),不参与分派,但可作 LIST/NESTED 元素或直接编码;
- 同一协议可挂多个父(UDP/TCP 同时挂 ipv4/ipv6);
- 常用引用形态:`LIST_TLV` 的元素、公共头的信令体,配合 `@Protocol(internal = true)` 不进侧栏。

## 2. 解码:StackDecoder(自顶向下)

从根协议开始:**解析一层 → 对已解析字段求值子绑定(`when`)→ 命中则从头部之后继续下降;没有命中就停在当前层,剩余字节原样保留**。

```java
StackDecoder decoder = registry.decoder();
DecodedPacket packet = decoder.decode(rawFrameBytes);   // 原始以太网帧进,整棵解析树出
```

- **只解析被 `@Protocol` 标记的协议** —— 未命中绑定(如 EtherType 0x0800 之外)的流量停在已注册层,不猜、不丢;这是机制保证,不是约定;
- 每层头部消费的字节数由 codec 的 `headerBytes()` 决定(长度驱动 @Payload 时停在 body 起点,尾随 CRC 不影响子层);
- 单帧解码异常只丢该帧,不杀解码线程。

## 3. 组装:StackEncoder(自内向外 + 自动接线)

```java
byte[] frame = registry.encoder().encode(List.of(ethernet, ipv4, udp, dnsQuery));
```

从最内层向外逐层包装,三件事全自动:

1. **选择子自动接线**:内层协议的 `when` 条件反推父层字段值 —— 挂在 `udp` 上条件 `dstPort==9000` 的协议,编码时父层 UDP 的 dstPort 自动填 9000,不用手工填(EtherType/IP protocol/端口号/你的信令类型字段同理);
2. **长度回填**:实现 `PayloadAware` 的层在注入内层字节后回调 `onPayload(inner)`,在这里算 `frameLength`/`totalLength`(IPv4 总长、UDP 长度都是这么做的);
3. **校验和两遍式回写**:`@ChecksumField` 置 0 → compute → 回写(见 annotation-reference.md §5)。

编码一致性防线:长度驱动 @Payload 与普通 BYTES 的 `lengthField` 若与实际值不符,序列化直接报错,不产出毒数据。

## 4. 注册表与 Spring 装配

- 裸用:`ProtocolRegistry.create(ProtocolClass1.class, ...)`;
- Spring Boot(starter):引入 `netproto-web` 后**自动扫描** `@Protocol` 类注册,入口零代码;`@BindOn` 父协议必须也在注册表内(内置栈 `com.netproto.protocols.builtin` 默认注册;多重 @BindOn 的全部父都要在册);
- 配置错误(重复 id、未知父、when 引用不存在的字段、注解校验失败)启动即 fail-fast。

## 5. 内置栈(`com.netproto.protocols.builtin`)

ethernet / vlan / arp / ipv4 / ipv6(固定基本头,扩展头链不下降,停在 ipv6 层)/ icmp / icmpv6 / udp / tcp。业务协议与内置栈走完全相同的机制 —— 你的协议就是栈上的一个普通节点。

诚实边界:IP 分片重组、TCP 流重组未实现(帧后处理器职责,`DecodedPacket` 消费接口已预留);IPv4 options 未建模(IHL 固定 5)。

## 6. 模块布局

| 模块 | 内容 | 依赖 |
|---|---|---|
| `netproto-core` | 注解、反射引擎、分派树、内置栈 | 仅 slf4j-api(零 Spring/pcap4j/Jackson) |
| `netproto-web` | Spring Boot starter:自动装配、观测台、REST/SSE、采集/发包 | core |
| `netproto-demo` | 演示应用:三套业务协议(智能配电/设备通信/物联网水利)+ 观测台 | web |

观测台(实时帧表格、层级字段树、hex/ASCII 选区、分层发包、pcap 导入导出)与 REST/SSE API 的使用说明见 README 对应章节。
