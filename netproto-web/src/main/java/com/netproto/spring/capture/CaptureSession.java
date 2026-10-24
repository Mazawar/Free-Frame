package com.netproto.spring.capture;

import com.netproto.stack.DecodedPacket;
import com.netproto.stack.StackDecoder;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.RawPacketListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * 单个采集会话:pcap4j 抓原始字节 → 有界队列 → 专属解码线程 → 摘要环形缓冲 + 订阅者推送。
 * <p>
 * 线程隔离:抓包线程(netproto-capture-*)只搬运字节入队,永不解码——解码/摘要/推送全部在
 * 解码线程(netproto-decode-*)串行完成。单会话解码 CPU 消耗有上界;线速超过解码能力时
 * 丢最旧帧并计数({@code queuedDropped}),kernel 侧丢帧由 pcap_stats 周期采样透出
 * ({@code kernelDropped})——压力以丢帧形式呈现,不会扩散成整机 CPU/GC 风暴。
 * <p>
 * 存储分层:缓冲与 SSE 常驻轻量 {@link FrameSummary}(原始字节 + 表格列),
 * 完整协议树不常驻——{@link #detail(long)} 按需用原始字节现场重解码。
 * 双上限淘汰最旧帧:帧数({@code ringSize})与原始字节预算({@code ringBytes})。
 * <p>
 * 关键点:全程不使用 pcap4j 的协议工厂(RawPacketListener 直接给 byte[])——
 * 只有注册过的 @Protocol 协议会被解析,这正是「只关注被标记的协议」的机制保证。
 */
public class CaptureSession {

    private static final Logger log = LoggerFactory.getLogger(CaptureSession.class);

    /** 待解码帧队列容量:抓包线程与解码线程之间的唯一缓冲(满 → 丢最旧保最新)。 */
    private static final int QUEUE_CAPACITY = 8192;

    private final String id;
    private final StackDecoder decoder;
    private final int ringSize;
    private final int ringBytes;
    private final int snaplen;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger captured = new AtomicInteger(0);
    private final AtomicLong queuedDropped = new AtomicLong(0);

    private final ArrayDeque<FrameSummary> ring = new ArrayDeque<>();
    private int ringRawBytes = 0;
    private final List<Consumer<FrameSummary>> listeners = new CopyOnWriteArrayList<>();
    /** 会话删除回调(如 SSE 连接发 session-closed 事件后关闭)。 */
    private final List<Runnable> closeCallbacks = new CopyOnWriteArrayList<>();

    private final ArrayBlockingQueue<Frame> pending = new ArrayBlockingQueue<>(QUEUE_CAPACITY);
    /** 解码线程代际:网卡异常自终止 + 亚秒级 restart 的窗口里,旧解码线程会读到新 running=true
     *  而"复活"(与新线程并存,stop 的 join/interrupt 从此管不到它)。代际令牌让被取代线程限期退出。 */
    private final AtomicInteger generation = new AtomicInteger();
    /** 订阅者(SSE 连接)计数:页面专属会话凭它判定"页面还开着吗"。 */
    private final AtomicInteger viewers = new AtomicInteger();
    private volatile long noViewerSince = System.currentTimeMillis();
    private volatile PcapHandle handle;
    private volatile Thread captureThread;
    private volatile Thread decodeThread;
    private volatile String currentIface;
    private volatile String bpf;
    private volatile PcapStat lastStats;
    private volatile long lastStatsAt = 0L;

    /** 队列元素:解码前帧的全部上下文(注入帧的 iface 是展示标签,与采集网卡独立)。 */
    private record Frame(String iface, byte[] raw, long ts) {}

    public CaptureSession(String id, StackDecoder decoder, int ringSize, int ringBytes, int snaplen) {
        this.id = id;
        this.decoder = decoder;
        this.ringSize = Math.max(16, ringSize);
        this.ringBytes = Math.max(64 * 1024, ringBytes);
        this.snaplen = snaplen;
    }

    public String id() {
        return id;
    }

    /** 开始采集(本会话自己的网卡句柄/BPF)。bpf 可为空(不过滤)。 */
    public synchronized void start(String iface, String bpf) throws PcapNativeException, NotOpenException {
        if (running.get()) {
            throw new IllegalStateException("session '" + id + "' already running on " + currentIface);
        }
        PcapHandle h = NetIfaces.find(iface).openLive(
                snaplen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        try {
            if (bpf != null && !bpf.isBlank()) {
                h.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);
            }
        } catch (Exception e) {
            // openLive 已成功而 setFilter 失败(非法表达式):必须回收句柄,
            // 否则每次非法 BPF start 都泄漏一个混杂模式 native pcap_t(可刷到驱动句柄耗尽)
            try {
                h.close();
            } catch (Exception closeFailure) {
                // 回收失败不掩盖原始错误
            }
            throw e;
        }
        this.handle = h;
        this.currentIface = iface;
        this.bpf = bpf == null ? "" : bpf;
        synchronized (ring) {
            ring.clear();
            ringRawBytes = 0;
        }
        pending.clear();
        captured.set(0);
        queuedDropped.set(0);
        lastStats = null;
        running.set(true);

        // 解码线程先起(队列先有消费者),抓包线程再产;代际令牌取代同会话任何旧解码线程
        int gen = generation.incrementAndGet();
        decodeThread = new Thread(() -> decodeLoop(gen), "netproto-decode-" + id);
        decodeThread.start();
        captureThread = new Thread(() -> captureLoop(h, iface), "netproto-capture-" + id);
        captureThread.start();
        log.info("session '{}' capture started on {} (bpf='{}')", id, iface, this.bpf);
    }

    /** 抓包线程体:只入队 + 周期采样 pcap_stats,解码永不发生在这里。 */
    private void captureLoop(PcapHandle h, String iface) {
        RawPacketListener raw = data -> {
            long now = System.currentTimeMillis();
            if (now - lastStatsAt > 1000) {
                lastStatsAt = now;
                try {
                    lastStats = h.getStats();
                } catch (Exception e) {
                    // 采样失败(平台不支持等)不影响抓包
                }
            }
            enqueue(iface, data, now);
        };
        try {
            h.loop(-1, raw);   // 无 pcap4j 协议工厂:只拿原始字节
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (PcapNativeException | NotOpenException e) {
            if (running.get()) {
                log.error("session '{}' capture loop error", id, e);
            }
        } finally {
            running.set(false);   // 解码线程排空队列后自行退出
            try {
                lastStats = h.getStats();
            } catch (Exception e) {
                // 句柄可能已不可用
            }
            if (h.isOpen()) {
                h.close();
            }
            log.info("session '{}' capture stopped on {}, total={}", id, iface, captured.get());
        }
    }

    /** 有界入队:满则丢最旧保最新(实时视图语义),丢弃计数。 */
    private void enqueue(String iface, byte[] raw, long ts) {
        Frame f = new Frame(iface, raw, ts);
        // 双生产者(capture 回调 + inject)下"poll 后必有空位"不成立:另一生产者可能抢先占位。
        // 循环重试保证最终入队,丢弃计数与实际挤掉的帧一一对应。
        while (!pending.offer(f)) {
            pending.poll();
            queuedDropped.incrementAndGet();
        }
    }

    /** 解码线程体:running=false 且队列排空后退出;单线程串行消费,帧序天然保序。
     *  被新一代 start 取代(异常终止后快速重启)时也退出,防线程复活累积。 */
    private void decodeLoop(int myGen) {
        try {
            while (generation.get() == myGen && (running.get() || !pending.isEmpty())) {
                Frame f = pending.poll(100, TimeUnit.MILLISECONDS);
                if (f != null) {
                    process(f);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();   // stop() 超时后的中断兜底
        }
    }

    /** 注入一帧原始字节(到达时间取当前时刻):走完整「入队 → 解码 → 摘要 → 推送」管线。 */
    public void inject(String iface, byte[] raw) {
        inject(iface, raw, System.currentTimeMillis());
    }

    /** 注入并指定时间戳(pcap 导入用:还原文件内的原始捕获时间)。
     *  会话运行中走队列(阻塞入队:注入帧不丢,与采集帧统一保序);
     *  会话停止后由调用线程内联处理(pcap 导入语义:导入本就要求先停止采集)。 */
    public void inject(String iface, byte[] raw, long tsMillis) {
        Thread worker = decodeThread;
        if (running.get() && worker != null && worker.isAlive()) {
            try {
                // 限时入队而非无限 put:stop 超时中断解码线程后队列可能满且再无消费者,
                // put 会永久阻塞 HTTP 线程(每重复一次挂掉一个 Tomcat worker)
                if (!pending.offer(new Frame(iface, raw, tsMillis), 2, TimeUnit.SECONDS)) {
                    throw new IllegalStateException(
                            "inject queue full (decoder backlogged or session stopping) — retry later");
                }
                return;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while queueing injected frame", e);
            }
        }
        process(new Frame(iface, raw, tsMillis));
    }

    /** 解码 + 摘要 + 环形缓冲 + 推送。单帧异常只丢该帧,不让解码线程死亡(队列还要消费)。 */
    private void process(Frame f) {
        try {
            // 采集热路径:关位区间簿记(详情由 detail() 按需重解码补全)
            DecodedPacket packet = decoder.decode(f.raw(), f.iface(), f.ts(),
                    captured.incrementAndGet(), false);
            FrameSummary summary = PacketSummarizer.summarize(packet);
            synchronized (ring) {
                ring.addLast(summary);
                ringRawBytes += f.raw().length;
                while (ring.size() > ringSize || ringRawBytes > ringBytes) {
                    FrameSummary evicted = ring.pollFirst();
                    if (evicted == null) {
                        break;
                    }
                    ringRawBytes -= evicted.raw().length;
                }
            }
            for (Consumer<FrameSummary> l : listeners) {
                try {
                    l.accept(summary);
                } catch (Exception e) {
                    log.warn("packet listener failed: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("session '{}' decode failed ({} bytes): {}", id, f.raw().length, e.getMessage());
        }
    }

    public synchronized void stop() {
        if (!running.get()) {
            return;
        }
        running.set(false);
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                log.debug("breakLoop on closed handle", e);
            }
        }
        joinQuietly(captureThread, 3000);
        // 解码线程在 running=false 后排空队列再退出;卡住则中断兜底
        joinQuietly(decodeThread, 3000);
        if (decodeThread != null && decodeThread.isAlive()) {
            decodeThread.interrupt();
        }
        // 丢弃本代残帧并放行仍在限时 offer 上等待的注入线程(stop 语义:停后帧不再入环)
        pending.clear();
    }

    private static void joinQuietly(Thread t, long ms) {
        if (t == null) {
            return;
        }
        try {
            t.join(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** 清空环形缓冲并重置计数(导入 pcap「打开文件」语义:展示的就是这份文件的内容)。 */
    public void reset() {
        synchronized (ring) {
            ring.clear();
            ringRawBytes = 0;
        }
        captured.set(0);
    }

    /** 会话删除:停止采集、清空缓冲,并通知订阅连接(如 SSE 发 session-closed 后断开)。 */
    public void close() {
        stop();
        reset();
        for (Runnable cb : closeCallbacks) {
            try {
                cb.run();
            } catch (Exception e) {
                log.warn("close callback failed: {}", e.getMessage());
            }
        }
    }

    /** 按 seq 重解码完整详情(树/字段/字节区间/hex)。帧已淘汰则 null。 */
    public DecodedPacket detail(long seq) {
        byte[] raw;
        String iface;
        long ts;
        synchronized (ring) {
            for (FrameSummary s : ring) {
                if (s.seq() == seq) {
                    raw = s.raw();
                    iface = s.iface();
                    ts = s.ts();
                    return decoder.decode(raw, iface, ts, (int) seq);
                }
            }
        }
        return null;
    }

    /** 对已有摘要直接重解码(信号视图等批量场景):调用方已持有 FrameSummary,
     *  免于 detail() 按 seq 全环线性回查 —— 后者单点是 O(ring),批量调用会持锁放大成 O(n×ring)。
     *  开位区间:信号视图靠 fieldRanges 判定字段是否真实解析(presentIf 缺席的默认值是假值)。 */
    public DecodedPacket decodeFrom(FrameSummary s) {
        return decoder.decode(s.raw(), s.iface(), s.ts(), (int) s.seq(), true);
    }

    /** 当前订阅者(SSE 连接)数:每会话连接数上限防护用。 */
    public int listenerCount() {
        return viewers.get();
    }

    /** 最近 n 帧摘要(新→旧)。 */
    public List<FrameSummary> recent(int limit) {
        return recent(limit, 0L);
    }

    /** 最近 n 帧摘要(新→旧);since>0 时只取 seq&gt;since 的帧(增量补拉),
     *  遇到更旧的即停(环内 seq 升序)—— 断线重连不再整环重发。 */
    public List<FrameSummary> recent(int limit, long since) {
        synchronized (ring) {
            int n = Math.min(Math.max(limit, 0), ring.size());
            List<FrameSummary> out = new ArrayList<>(n);
            java.util.Iterator<FrameSummary> it = ring.descendingIterator();
            for (int i = 0; i < n && it.hasNext(); i++) {
                FrameSummary s = it.next();
                if (since > 0 && s.seq() <= since) {
                    break;
                }
                out.add(s);
            }
            return out;
        }
    }

    public void addListener(Consumer<FrameSummary> listener) {
        listeners.add(listener);
        if (viewers.incrementAndGet() == 1) {
            noViewerSince = 0L;   // 有人订阅:不参与空闲回收
        }
    }

    public void removeListener(Consumer<FrameSummary> listener) {
        if (listeners.remove(listener) && viewers.decrementAndGet() == 0) {
            noViewerSince = System.currentTimeMillis();   // 无订阅者的起点(页面刷新的断连空窗也由此计时)
        }
    }

    /** 已连续无订阅者(SSE 连接)的时长 ms;仍有订阅者返回 0。页面专属会话的生死即以此映射。 */
    public long millisWithoutViewers() {
        long since = noViewerSince;
        return since == 0L ? 0L : System.currentTimeMillis() - since;
    }

    public void addCloseCallback(Runnable callback) {
        closeCallbacks.add(callback);
    }

    public void removeCloseCallback(Runnable callback) {
        closeCallbacks.remove(callback);
    }

    public boolean isRunning() {
        return running.get();
    }

    /** 当前采集网卡名(从未采集过为 null)。 */
    public String iface() {
        return currentIface;
    }

    /** 状态视图:旧键(running/iface/captured/ringSize/frames/bytes)保持不变,新键只增不改。 */
    public Map<String, Object> status() {
        int frames;
        int bytes;
        synchronized (ring) {
            frames = ring.size();
            bytes = ringRawBytes;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("sessionId", id);
        m.put("running", running.get());
        m.put("iface", currentIface == null ? "" : currentIface);
        m.put("bpf", bpf == null ? "" : bpf);
        m.put("captured", captured.get());
        m.put("queuedDropped", queuedDropped.get());
        PcapStat st = lastStats;
        if (st != null) {
            m.put("kernelDropped", st.getNumPacketsDropped());
            m.put("ifaceDropped", st.getNumPacketsDroppedByIf());
        }
        m.put("ringSize", ringSize);
        m.put("frames", frames);
        m.put("bytes", bytes);
        return m;
    }
}
