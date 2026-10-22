package com.netproto.spring.capture;

import com.netproto.stack.StackDecoder;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 会话表:default 兼容会话(旧版无会话维度的端点全部落在它上面,懒创建)+
 * 显式命名会话(各自独立网卡句柄/BPF/缓冲/序号——多页面并行抓不同包的基础)。
 * <p>
 * 上限 {@code maxSessions}(含 default 预留):每会话占一个 native 捕获句柄 + 两条线程,
 * 上限护资源;DELETE 会话释放名额。default 删除后下次旧端点调用懒重建,语义无状态。
 */
public class SessionManager {

    public static final String DEFAULT_ID = "default";

    private final StackDecoder decoder;
    private final int ringSize;
    private final int ringBytes;
    private final int snaplen;
    private final int maxSessions;

    private final Map<String, CaptureSession> sessions = new ConcurrentHashMap<>();
    private final AtomicLong seq = new AtomicLong();

    public SessionManager(StackDecoder decoder, int ringSize, int ringBytes, int snaplen, int maxSessions) {
        this.decoder = decoder;
        this.ringSize = Math.max(16, ringSize);
        this.ringBytes = Math.max(64 * 1024, ringBytes);
        this.snaplen = snaplen;
        this.maxSessions = Math.max(2, maxSessions);
    }

    /** default 会话懒创建:旧端点(/capture/start、/stream 等)的固定落点。 */
    public CaptureSession defaultSession() {
        return sessions.computeIfAbsent(DEFAULT_ID, this::newSession);
    }

    /** 新建并启动一个会话;超上限抛 IllegalStateException(控制器预先检查转 409)。 */
    public synchronized CaptureSession create(String iface, String bpf)
            throws PcapNativeException, NotOpenException {
        if (!canCreate()) {
            throw new IllegalStateException("session limit reached: " + maxSessions
                    + " concurrent sessions max — delete one first");
        }
        String id = "s" + seq.incrementAndGet();
        CaptureSession s = newSession(id);
        s.start(iface, bpf);
        sessions.put(id, s);
        return s;
    }

    /** 是否还有名额(default 未创建时为其预留一个位置,保证旧端点随时可用)。 */
    public boolean canCreate() {
        int count = sessions.size() + (sessions.containsKey(DEFAULT_ID) ? 0 : 1);
        return count < maxSessions;
    }

    public CaptureSession get(String id) {
        return sessions.get(id);
    }

    /** 删除会话:停止采集、释放缓冲并通知订阅连接。返回 false = 会话不存在。 */
    public synchronized boolean delete(String id) {
        CaptureSession s = sessions.remove(id);
        if (s == null) {
            return false;
        }
        s.close();
        return true;
    }

    /** 全部会话(default 在前,其余按 id 字典序≈创建序)。 */
    public List<CaptureSession> all() {
        List<CaptureSession> out = new ArrayList<>(sessions.values());
        out.sort(Comparator.comparing(s -> s.id().equals(DEFAULT_ID) ? "" : s.id()));
        return out;
    }

    public int maxSessions() {
        return maxSessions;
    }

    protected CaptureSession newSession(String id) {
        return new CaptureSession(id, decoder, ringSize, ringBytes, snaplen);
    }
}
