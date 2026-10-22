# 引擎吞吐边界压测报告(2026-10-22)

**对象**:`netproto-core` StackDecoder / StackEncoder + demo 三套业务协议(pd 9000 / dev 9001 / iot 9002),注册表 49 个协议,根协议 ethernet。

**方法**:手写 harness(`netproto-demo/src/test/java/com/netproto/demo/bench/EngineBench.java`),非 JMH。每场景预热 2 轮 + 测量 8 轮(各 1s),取峰值轮;blackhole 累计防死码消除。共跑 3 次(4/4/8 轮),报告取多轮一致的峰值,波动大的给区间。

**环境**:JDK 25(G1,默认参数)/ Intel 12 代 20 逻辑核(P+E 混合,笔记本)/ Windows 11 / 后台有常驻服务。混合核 + 后台负载导致运行间波动可达 2x,表中数值为多轮一致的峰值(乐观界)。

复现:`./mvnw -pl netproto-demo org.codehaus.mojo:exec-maven-plugin:3.2.0:java -Dexec.mainClass=com.netproto.demo.bench.EngineBench -Dexec.classpathScope=test -Dbench.rounds=8`

## 解码(单线程)

| 场景 | 帧长 | µs/帧 | 帧率 | 带宽 |
|---|---|---|---|---|
| eth-only(单层地板) | 14B | 0.4–0.5 | **~190–253 万帧/s** | 33 MB/s |
| eth▸ip▸udp▸未注册(payload 原样) | 1KB | 4.8 | 20.7 万帧/s | 211 MB/s |
| 同上 | 8KB | 6.3 | 15.8 万帧/s | 1.24 GB/s |
| 同上 | 60KB | 23–45 | 4.3–5.6 万帧/s | **2.5–3.3 GB/s** |
| eth▸ip▸udp▸pd▸pd-heartbeat(5 层) | 59B | 5.9 | **17 万帧/s** | 9.5 MB/s |
| eth▸ip▸udp▸pd▸pd-status(5 层) | 64B | 6.5 | 15.3 万帧/s | 9.3 MB/s |
| eth▸ip▸udp▸dev▸dev-reg(5 层) | 53B | 5.4 | 18.6 万帧/s | 9.4 MB/s |
| iot-dev-cfg 计数列表 10 条 | 223B | 28 | 3.6–7.4 万帧/s | — |
| iot-dev-cfg 100 条 | 1.6KB | 154 | 6.5–9.3 千帧/s | — |
| iot-dev-cfg 1000 条 | 16KB | 695–800 | 1.4–2.2 千帧/s | — |
| 混合 4 种业务帧轮换 | ~63B | 13 | 7.5–11.7 万帧/s | — |
| 畸形帧(pd 帧全部 58 种截断前缀) | ≤59B | 3.4 | **11–29 万帧/s,零崩溃** | — |

## 编码(单线程,POJO 池轮换)

| 场景 | 帧长 | µs/帧 | 帧率 | 带宽 |
|---|---|---|---|---|
| eth▸ip▸udp▸raw | 1KB | 13.1 | 7.6 万帧/s | 78 MB/s |
| 同上 | 8KB | 16.6 | 6.0 万帧/s | 473 MB/s |
| 同上 | 60KB | 26 | 3.9 万帧/s | **2.3 GB/s** |
| 5 层业务小帧(pd-hb / pd-status / dev-reg) | 50–63B | 8.7–9.9 | **10–11.5 万帧/s** | ~6 MB/s |
| iot 列表 10 / 100 / 1000 条 | — | 19 / 98 / 885 | 5.4万 / 1.0万 / 1.1千 | — |

## 往返(encode + decode)

| 场景 | µs/次 | 次数/s |
|---|---|---|
| 5 层业务小帧 | 14–17 | **~6 万往返/s** |
| iot 100 条 | 173–274 | 3.6–5.8 千/s |

## 并发解码(混合语料,每档 3s)

| 线程 | 吞吐 | ConcurrentModificationException |
|---|---|---|
| 1 | 12–15 万帧/s | 0 |
| 2 | 24–27 万 | 4–5 万次 |
| 4 | **33–34 万(峰值)** | 52–60 万次 |
| 8 | 25–27 万(回落) | 230–250 万次 |
| 16 | 19–22 万(负增长) | 470–500 万次 |

## 结论:边界在哪

1. **引擎是"帧率受限"而非"带宽受限"**:小帧(64B)15–18 万帧/s ≈ **百兆线速(14.88 万 pps)边界**;大帧 2.5–3.3 GB/s 超 20GbE 带宽。千兆小帧线速(148 万 pps)差 8–10 倍,是当前架构的数量级天花板。
2. **每注册层 ~1–1.4µs**:5 层栈 5.4–6.7µs。成本构成:每层两个 LinkedHashMap 位区间簿记 + matchChild 条件求值 + 反射字段 setAccessible。未注册层的 payload 只引用不拷贝,但 @Payload 提取拷贝 ~3 GB/s 封顶(60KB 帧带宽界)。
3. **列表线性扩展**:计数列表每条目解码 ~0.5–0.7µs、编码 ~0.9µs,无超线性退化。
4. **畸形帧健壮**:58 种截断前缀全部安全停下(逐层 try/catch),成本与正常帧同量级甚至更快(提前终止)。
5. **并发既不安全也不扩展**:`ProtocolCodec.lastFieldRanges` 是 codec 单例上的可变 HashMap(源码注释自述"分派线程内单线程使用"),`StackDecoder` 解码后立即读它 → 多线程解码海量 ConcurrentModificationException;吞吐 4 线程封顶 ~2.5x,8 线程起负增长。**当前安全模型 = 单线程采集管道**(现网 CaptureEngine 正是单线程,故线上无恙)。

## 若要提吞吐(按性价比)

1. `lastFieldRanges` 改为解码返回值携带或 ThreadLocal 化 → 同时解决线程安全与并发扩展;
2. 位区间簿记惰性化(仅 UI 选帧时重算)→ 预计砍掉每层约一半对象分配;
3. `Field`/`setAccessible` 构造期一次性缓存(编码侧 `findFieldByName` 每次序列化都线性扫描 getDeclaredFields);
4. 需要千兆小帧线速时:按 CPU 栈分片并行(先做 1),或对热路径协议提供生成代码快路径。

## 与引擎加固缺口的关系

本次压测实证了自审清单中的并发缺口(lastFieldRanges);越界/溢出类缺口在畸形帧全扫中未触发崩溃(逐层 try/catch 兜底),但"截断帧静默降层"在 UI 上表现为帧层数变少,属可接受行为。
