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
 * 采集引擎:pcap4j 抓原始字节 → StackDecoder 自顶向下解析 → 环形缓冲 + 订阅者推送。
 * <p>
 * 关键点:全程不使用 pcap4j 的协议工厂(RawPacketListener 直接给 byte[])——
 * 只有注册过的 @Protocol 协议会被解析,这正是「只关注被标记的协议」的机制保证。
 */
public class CaptureEngine {

    private static final Logger log = LoggerFactory.getLogger(CaptureEngine.class);

    private final StackDecoder decoder;
    private final int ringSize;
    private final int snaplen;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger captured = new AtomicInteger(0);
    private final ArrayDeque<DecodedPacket> ring = new ArrayDeque<>();
    private final List<Consumer<DecodedPacket>> listeners = new CopyOnWriteArrayList<>();

    private volatile PcapHandle handle;
    private volatile Thread captureThread;
    private volatile String currentIface;

    public CaptureEngine(StackDecoder decoder, int ringSize, int snaplen) {
        this.decoder = decoder;
        this.ringSize = Math.max(16, ringSize);
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
        }
        captured.set(0);

        captureThread = new Thread(() -> {
            RawPacketListener raw = data -> accept(iface, data);
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

    /** 注入一帧原始字节(到达时间取当前时刻):走完整「解析 → 环形缓冲 → 订阅者推送」管线。 */
    public void inject(String iface, byte[] raw) {
        inject(iface, raw, System.currentTimeMillis());
    }

    /** 注入并指定时间戳(pcap 导入用:还原文件内的原始捕获时间)。 */
    public void inject(String iface, byte[] raw, long tsMillis) {
        accept(iface, raw, tsMillis);
    }

    /** 解析一帧并广播(包内可见,测试用)。 */
    void accept(String iface, byte[] raw) {
        accept(iface, raw, System.currentTimeMillis());
    }

    void accept(String iface, byte[] raw, long tsMillis) {
        int seq = captured.incrementAndGet();
        DecodedPacket packet = decoder.decode(raw, iface, tsMillis, seq);
        synchronized (ring) {
            ring.addLast(packet);
            while (ring.size() > ringSize) {
                ring.pollFirst();
            }
        }
        for (Consumer<DecodedPacket> l : listeners) {
            try {
                l.accept(packet);
            } catch (Exception e) {
                log.warn("packet listener failed: {}", e.getMessage());
            }
        }
    }

    /** 最近 n 帧(新→旧)。 */
    public List<DecodedPacket> recent(int limit) {
        synchronized (ring) {
            int n = Math.min(Math.max(limit, 0), ring.size());
            List<DecodedPacket> out = new ArrayList<>(n);
            java.util.Iterator<DecodedPacket> it = ring.descendingIterator();
            for (int i = 0; i < n && it.hasNext(); i++) {
                out.add(it.next());
            }
            return out;
        }
    }

    public void addListener(Consumer<DecodedPacket> listener) {
        listeners.add(listener);
    }

    public void removeListener(Consumer<DecodedPacket> listener) {
        listeners.remove(listener);
    }

    public boolean isRunning() {
        return running.get();
    }

    public Map<String, Object> status() {
        return Map.of(
                "running", running.get(),
                "iface", currentIface == null ? "" : currentIface,
                "captured", captured.get(),
                "ringSize", ringSize);
    }
}
