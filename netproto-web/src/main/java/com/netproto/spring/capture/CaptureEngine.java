package com.netproto.spring.capture;

import com.netproto.stack.DecodedPacket;
import com.netproto.stack.StackDecoder;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.RawPacketListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * 采集引擎:pcap4j 抓原始字节 → StackDecoder 自顶向下解析 → 摘要环形缓冲 + 订阅者推送。
 * <p>
 * Wireshark 式存储分层:缓冲与 SSE 常驻轻量 {@link FrameSummary}(原始字节 + 表格列),
 * 完整协议树不常驻——{@link #detail(long)} 按需用原始字节现场重解码。
 * 双上限淘汰最旧帧:帧数({@code ringSize},护列表规模)与原始字节预算({@code ringBytes},护内存)。
 * <p>
 * 关键点:全程不使用 pcap4j 的协议工厂(RawPacketListener 直接给 byte[])——
 * 只有注册过的 @Protocol 协议会被解析,这正是「只关注被标记的协议」的机制保证。
 */
public class CaptureEngine {

    private static final Logger log = LoggerFactory.getLogger(CaptureEngine.class);

    private final StackDecoder decoder;
    private final int ringSize;
    private final int ringBytes;
    private final int snaplen;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger captured = new AtomicInteger(0);
    private final ArrayDeque<FrameSummary> ring = new ArrayDeque<>();
    private int ringRawBytes = 0;
    private final List<Consumer<FrameSummary>> listeners = new CopyOnWriteArrayList<>();

    private volatile PcapHandle handle;
    private volatile Thread captureThread;
    private volatile String currentIface;

    public CaptureEngine(StackDecoder decoder, int ringSize, int ringBytes, int snaplen) {
        this.decoder = decoder;
        this.ringSize = Math.max(16, ringSize);
        this.ringBytes = Math.max(64 * 1024, ringBytes);
        this.snaplen = snaplen;
    }

    /** 开始采集。bpf 可为空(不过滤)。 */
    public synchronized void start(String iface, String bpf) throws PcapNativeException, NotOpenException {
        if (running.get()) {
            throw new IllegalStateException("capture already running on " + currentIface);
        }
        PcapHandle h = NetIfaces.find(iface).openLive(
                snaplen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        if (bpf != null && !bpf.isBlank()) {
            h.setFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE);
        }
        this.handle = h;
        this.currentIface = iface;
        running.set(true);
        synchronized (ring) {
            ring.clear();
            ringRawBytes = 0;
        }
        captured.set(0);

        captureThread = new Thread(() -> {
            RawPacketListener raw = data -> accept(iface, data, System.currentTimeMillis());
            try {
                h.loop(-1, raw);   // 无 pcap4j 协议工厂:只拿原始字节
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (PcapNativeException | NotOpenException e) {
                if (running.get()) {
                    log.error("capture loop error", e);
                }
            } finally {
                running.set(false);
                if (h.isOpen()) {
                    h.close();
                }
                log.info("capture stopped on {}, total={}", iface, captured.get());
            }
        }, "netproto-capture");
        captureThread.start();
        log.info("capture started on {} (bpf='{}')", iface, bpf == null ? "" : bpf);
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
        if (captureThread != null) {
            captureThread.interrupt();
            try {
                captureThread.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
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

    /** 注入一帧原始字节(到达时间取当前时刻):走完整「解析 → 摘要 → 环形缓冲 → 推送」管线。 */
    public void inject(String iface, byte[] raw) {
        inject(iface, raw, System.currentTimeMillis());
    }

    /** 注入并指定时间戳(pcap 导入用:还原文件内的原始捕获时间)。 */
    public void inject(String iface, byte[] raw, long tsMillis) {
        accept(iface, raw, tsMillis);
    }

    void accept(String iface, byte[] raw) {
        accept(iface, raw, System.currentTimeMillis());
    }

    void accept(String iface, byte[] raw, long tsMillis) {
        // 采集热路径:关位区间簿记(详情由 detail() 按需重解码补全)
        DecodedPacket packet = decoder.decode(raw, iface, tsMillis, captured.incrementAndGet(), false);
        FrameSummary summary = PacketSummarizer.summarize(packet);
        synchronized (ring) {
            ring.addLast(summary);
            ringRawBytes += raw.length;
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

    /** 最近 n 帧摘要(新→旧)。 */
    public List<FrameSummary> recent(int limit) {
        synchronized (ring) {
            int n = Math.min(Math.max(limit, 0), ring.size());
            List<FrameSummary> out = new ArrayList<>(n);
            java.util.Iterator<FrameSummary> it = ring.descendingIterator();
            for (int i = 0; i < n && it.hasNext(); i++) {
                out.add(it.next());
            }
            return out;
        }
    }

    public void addListener(Consumer<FrameSummary> listener) {
        listeners.add(listener);
    }

    public void removeListener(Consumer<FrameSummary> listener) {
        listeners.remove(listener);
    }

    public boolean isRunning() {
        return running.get();
    }

    public Map<String, Object> status() {
        int frames;
        int bytes;
        synchronized (ring) {
            frames = ring.size();
            bytes = ringRawBytes;
        }
        return Map.of(
                "running", running.get(),
                "iface", currentIface == null ? "" : currentIface,
                "captured", captured.get(),
                "ringSize", ringSize,
                "frames", frames,
                "bytes", bytes);
    }
}
