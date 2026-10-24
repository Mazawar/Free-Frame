package com.netproto.spring.capture;

import com.netproto.stack.StackDecoder;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 会话表:default 兼容会话(旧版无会话维度的端点全部落在它上面,懒创建)+
 * 显式命名会话(各自独立网卡句柄/BPF/缓冲/序号——多页面并行抓不同包的基础)。
 * <p>
 * 上限 {@code maxSessions}(含 default 预留):每会话占一个 native 捕获句柄 + 两条线程,
 * 上限护资源;DELETE 会话释放名额。default 删除后下次旧端点调用懒重建,语义无状态。
 * <p>
 * 页面稳定会话模型:命名会话的生死映射其页面——SSE 连接即页面心跳,无订阅者超过
 * 宽限期(默认 60s,远大于刷新页面的断连空窗)由清扫线程停止并回收;
 * default 豁免(兼容 curl 等无订阅者的传统用法)。
 */
public class SessionManager {

    private static final Logger log = LoggerFactory.getLogger(SessionManager.class);

    public static final String DEFAULT_ID = "default";

    private static final long DEFAULT_IDLE_GRACE_MS = 60_000;

    private final StackDecoder decoder;
    private final int ringSize;
    private final int ringBytes;
    private final int snaplen;
    private final int maxSessions;
    private final long idleGraceMs;

    private final Map<String, CaptureSession> sessions = new ConcurrentHashMap<>();
    private final AtomicLong seq = new AtomicLong();
    private final ScheduledExecutorService sweeper;

    public SessionManager(StackDecoder decoder, int ringSize, int ringBytes, int snaplen, int maxSessions) {
        this(decoder, ringSize, ringBytes, snaplen, maxSessions, DEFAULT_IDLE_GRACE_MS);
    }

    public SessionManager(StackDecoder decoder, int ringSize, int ringBytes, int snaplen,
                          int maxSessions, long idleGraceMs) {
        this.decoder = decoder;
        this.ringSize = Math.max(16, ringSize);
        this.ringBytes = Math.max(64 * 1024, ringBytes);
        this.snaplen = snaplen;
        this.maxSessions = Math.max(2, maxSessions);
        this.idleGraceMs = idleGraceMs;
        if (idleGraceMs > 0) {
            this.sweeper = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "netproto-session-sweeper");
                t.setDaemon(true);
                return t;
            });
            sweeper.scheduleWithFixedDelay(this::sweepIdleSessions, 10, 10, TimeUnit.SECONDS);
        } else {
            this.sweeper = null;   // 测试用手动模式(直接调 sweepIdleSessions)
        }
    }

    /** Spring @Bean 销毁回调(方法名自动推断)。
     *  必须关停全部会话:采集/解码线程非 daemon,h.loop(-1) 只有 breakLoop 能醒——
     *  不关的话运行中关停应用,两个 netproto-capture-* 线程会让 JVM 永不退出(容器被 SIGKILL)。 */
    public void shutdown() {
        if (sweeper != null) {
            sweeper.shutdownNow();
        }
        for (CaptureSession s : List.copyOf(sessions.values())) {
            try {
                s.close();
            } catch (Exception e) {
                log.warn("session '{}' failed to close during shutdown: {}", s.id(), e.getMessage());
            }
        }
        sessions.clear();
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

    /** 重启已有(已停止的)会话:同一会话 id,环形缓冲清空、序号从 1 重新计数。
     *  返回 null = 会话不存在;已在运行抛 IllegalStateException(控制器预检转 409)。 */
    public synchronized CaptureSession restart(String id, String iface, String bpf)
            throws PcapNativeException, NotOpenException {
        CaptureSession s = sessions.get(id);
        if (s == null) {
            return null;
        }
        s.start(iface, bpf);
        return s;
    }

    /**
     * 空闲注册(页面加载即占位):存在则原样返回(幂等),不存在则创建但**不启动采集**——
     * 「采集」由带 iface 的注册或 restart 触发。清扫器保证页面关闭后占位自动释放。
     */
    public synchronized CaptureSession registerIdle(String id) {
        validateId(id);
        CaptureSession existing = sessions.get(id);
        if (existing != null) {
            return existing;
        }
        if (!canCreate()) {
            throw new IllegalStateException("session limit reached: " + maxSessions
                    + " concurrent sessions max — delete one first");
        }
        CaptureSession s = newSession(id);
        sessions.put(id, s);
        return s;
    }

    /**
     * 注册页面自带的会话 id(UUID):不存在则创建并启动,存在且已停止则重启——
     * 后端重启/会话被回收后页面凭同一 id 重新注册,身份永不换。
     */
    public synchronized CaptureSession register(String id, String iface, String bpf)
            throws PcapNativeException, NotOpenException {
        validateId(id);
        CaptureSession existing = sessions.get(id);
        if (existing != null) {
            existing.start(iface, bpf);   // 已在运行由控制器预检转 409
            return existing;
        }
        if (!canCreate()) {
            throw new IllegalStateException("session limit reached: " + maxSessions
                    + " concurrent sessions max — delete one first");
        }
        CaptureSession s = newSession(id);
        s.start(iface, bpf);
        sessions.put(id, s);
        return s;
    }

    /** 会话 id 规则:[A-Za-z0-9_-]{4,64},default 保留(→400)。 */
    private static void validateId(String id) {
        if (id == null || !id.matches("[A-Za-z0-9_-]{4,64}")) {
            throw new IllegalArgumentException(
                    "invalid session id (4-64 chars of A-Za-z0-9_-): " + id);
        }
        if (DEFAULT_ID.equals(id)) {
            throw new IllegalArgumentException("session id '" + DEFAULT_ID + "' is reserved");
        }
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

    /** 空闲回收:命名会话连续无任何 SSE 订阅者超过宽限期 → 停止并删除(页面关闭即回收;
     *  刷新的断连空窗远小于宽限期,不会误杀)。default 豁免:传统 curl 用法常无订阅者。 */
    synchronized void sweepIdleSessions() {
        for (CaptureSession s : List.copyOf(sessions.values())) {
            if (DEFAULT_ID.equals(s.id())) {
                continue;
            }
            long idle = s.millisWithoutViewers();
            if (idle >= idleGraceMs) {
                sessions.remove(s.id());
                s.close();
                log.info("session '{}' idle for {}ms (page closed?) — reaped", s.id(), idle);
            }
        }
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
