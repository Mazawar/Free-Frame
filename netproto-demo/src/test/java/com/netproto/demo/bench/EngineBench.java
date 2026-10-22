package com.netproto.demo.bench;

import com.netproto.annotation.Protocol;
import com.netproto.demo.protocol.devcomm.DevFrame;
import com.netproto.demo.protocol.devcomm.DevReg;
import com.netproto.demo.protocol.iot.IotCfgItem;
import com.netproto.demo.protocol.iot.IotDevCfg;
import com.netproto.demo.protocol.iot.IotFrame;
import com.netproto.demo.protocol.powerdist.PdFrame;
import com.netproto.demo.protocol.powerdist.PdHeartbeat;
import com.netproto.demo.protocol.powerdist.PdStatusReport;
import com.netproto.protocols.builtin.EthernetFrame;
import com.netproto.protocols.builtin.Ipv4Packet;
import com.netproto.protocols.builtin.UdpSegment;
import com.netproto.stack.DecodedPacket;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackDecoder;
import com.netproto.stack.StackEncoder;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 引擎吞吐边界基准(手写 harness,非 JMH):
 * 预热 2 轮 + 测量 4 轮(各 1s),取峰值轮与中位轮;blackhole 累计防死码消除。
 * 场景:单层/原始 payload(尺寸缩放)/三套业务栈/计数列表(条目缩放)/畸形截断帧/并发扩展性。
 * 输出全部 ASCII,避免 Windows 控制台编码问题。
 */
public class EngineBench {

    static ProtocolRegistry registry;
    static StackDecoder decoder;
    static StackEncoder encoder;
    static volatile long sink;   // blackhole:累计 layers 数与路径长度

    static final long WARMUP_ROUNDS = 2;
    static final long MEASURE_ROUNDS = Long.getLong("bench.rounds", 4);
    static final long ROUND_MS = Long.getLong("bench.roundMs", 1000);

    public static void main(String[] args) throws Exception {
        List<Class<?>> classes = new ArrayList<>();
        classes.addAll(scan("com.netproto.protocols.builtin"));
        classes.addAll(scan("com.netproto.demo.protocol"));
        registry = ProtocolRegistry.create(classes);
        registry.validateBindings();
        decoder = new StackDecoder(registry, "ethernet");
        encoder = new StackEncoder(registry);

        System.out.printf("env: jdk=%s cores=%d registry=%d root=ethernet%n",
                System.getProperty("java.version"), Runtime.getRuntime().availableProcessors(), registry.all().size());
        System.out.printf("      warmup=%d rounds measure=%d rounds round=%dms%n%n", WARMUP_ROUNDS, MEASURE_ROUNDS, ROUND_MS);

        // ============ 解码 ============
        header("DECODE");
        byte[] ethOnly = encoder.encode(List.of(eth()));
        benchDecode("eth-only 14B", new byte[][]{ethOnly});

        for (int kb : new int[]{1, 8, 60}) {
            byte[][] corpus = new byte[][]{rawUdpFrame(kb * 1024)};
            benchDecode("eth-ip-udp>raw " + kb + "KB", corpus);
        }
        benchDecode("pd-heartbeat ~62B", corpusOf(FrameKind.PD_HB, 1));
        benchDecode("pd-status ~63B", corpusOf(FrameKind.PD_STATUS, 1));
        benchDecode("dev-reg ~50B", corpusOf(FrameKind.DEV_REG, 1));
        for (int n : new int[]{10, 100, 1000}) {
            benchDecode("iot-dev-cfg " + n + " entries", corpusOf(FrameKind.IOT_CFG, n));
        }
        benchDecode("mixed 4 business frames", mixedCorpus());

        // ============ 编码 ============
        header("ENCODE");
        for (int kb : new int[]{1, 8, 60}) {
            benchEncode("eth-ip-udp>raw " + kb + "KB", poolOfRaw(kb * 1024, 512));
        }
        benchEncode("pd-heartbeat ~62B", poolOf(FrameKind.PD_HB, 1, 1024));
        benchEncode("pd-status ~63B", poolOf(FrameKind.PD_STATUS, 1, 1024));
        benchEncode("dev-reg ~50B", poolOf(FrameKind.DEV_REG, 1, 1024));
        for (int n : new int[]{10, 100, 1000}) {
            benchEncode("iot-dev-cfg " + n + " entries", poolOf(FrameKind.IOT_CFG, n, 64));
        }

        // ============ 往返 ============
        header("ROUND-TRIP (encode+decode)");
        benchRoundTrip("pd-heartbeat", FrameKind.PD_HB, 1);
        benchRoundTrip("pd-status", FrameKind.PD_STATUS, 1);
        benchRoundTrip("dev-reg", FrameKind.DEV_REG, 1);
        benchRoundTrip("iot-dev-cfg 100 entries", FrameKind.IOT_CFG, 100);

        // ============ 畸形帧(截断前缀全扫) ============
        header("MALFORMED (truncated prefixes)");
        byte[] full = encoder.encode(stack(FrameKind.PD_HB, 1).layers());
        List<byte[]> prefixes = new ArrayList<>();
        prefixes.add(new byte[0]);
        for (int len = 1; len < full.length; len++) prefixes.add(java.util.Arrays.copyOf(full, len));
        benchDecode("pd-frame " + (full.length - 1) + " truncations", prefixes.toArray(new byte[0][]));

        // ============ 并发 ============
        header("CONCURRENCY (decode, mixed corpus)");
        byte[][] mixed = mixedCorpus();
        for (int threads : new int[]{1, 2, 4, 8, 16}) {
            benchConcurrentDecode(threads, mixed);
        }

        System.out.printf("%nblackhole sink = %d (must be nonzero)%n", sink);
    }

    // ---------------- 场景构造 ----------------

    enum FrameKind {PD_HB, PD_STATUS, DEV_REG, IOT_CFG}

    /** 一套可编码的 POJO 栈(encode 会改写这些对象,池化轮换)。 */
    record Stack(List<Object> layers, int approxBytes) {}

    static Stack stack(FrameKind kind, int listSize) {
        return switch (kind) {
            case PD_HB -> new Stack(List.of(eth(), ip(), udp(40001, 9000), new PdFrame(), new PdHeartbeat()), 62);
            case PD_STATUS -> new Stack(List.of(eth(), ip(), udp(40002, 9000), new PdFrame(), new PdStatusReport()), 63);
            case DEV_REG -> {
                DevReg reg = new DevReg();
                reg.setSecurity(0);
                yield new Stack(List.of(eth(), ip(), udp(40003, 9001), new DevFrame(), reg), 50);
            }
            case IOT_CFG -> {
                IotFrame f = new IotFrame();
                f.setFrameType(1);
                IotDevCfg cfg = new IotDevCfg();
                cfg.setEntryCount(listSize);
                List<IotCfgItem> items = new ArrayList<>(listSize);
                for (int i = 0; i < listSize; i++) {
                    items.add(IotCfgItem.of(i + 1, String.format("S%05d", i).getBytes(), 0x0102));   // 名称定长 6B
                }
                cfg.setEntries(items);
                yield new Stack(List.of(eth(), ip(), udp(40004, 9002), f, cfg), 42 + 17 + listSize * 16 + 4);
            }
        };
    }

    static byte[][] corpusOf(FrameKind kind, int listSize) {
        return new byte[][]{encoder.encode(stack(kind, listSize).layers())};
    }

    static byte[][] mixedCorpus() {
        return new byte[][]{
                encoder.encode(stack(FrameKind.PD_HB, 1).layers()),
                encoder.encode(stack(FrameKind.PD_STATUS, 1).layers()),
                encoder.encode(stack(FrameKind.DEV_REG, 1).layers()),
                encoder.encode(stack(FrameKind.IOT_CFG, 1).layers()),
        };
    }

    static byte[] rawUdpFrame(int payloadBytes) {
        return encoder.encode(poolOfRaw(payloadBytes, 1)[0].layers());
    }

    static Stack[] poolOfRaw(int payloadBytes, int poolSize) {
        Stack[] pool = new Stack[poolSize];
        for (int i = 0; i < poolSize; i++) {
            UdpSegment u = udp(51000 + i, 9999);
            u.setPayload(new byte[payloadBytes]);
            pool[i] = new Stack(List.of(eth(), ip(), u), 42 + payloadBytes);
        }
        return pool;
    }

    static Stack[] poolOf(FrameKind kind, int listSize, int poolSize) {
        Stack[] pool = new Stack[poolSize];
        for (int i = 0; i < poolSize; i++) pool[i] = stack(kind, listSize);
        return pool;
    }

    static EthernetFrame eth() {
        EthernetFrame e = new EthernetFrame();
        e.setDstMac(0xFFFFFFFFFFFFL);
        e.setSrcMac(0x020000000001L);
        return e;
    }

    static Ipv4Packet ip() {
        Ipv4Packet p = new Ipv4Packet();
        p.setSourceIp(0xC0A80164);      // 192.168.1.100
        p.setDestinationIp(0xC0A801C8); // 192.168.1.200
        return p;
    }

    static UdpSegment udp(int src, int dst) {
        UdpSegment u = new UdpSegment();
        u.setSrcPort(src);
        u.setDstPort(dst);
        return u;
    }

    // ---------------- 测量内核 ----------------

    static void header(String title) {
        System.out.println("================ " + title + " ================");
        System.out.printf("%-28s %10s %12s %10s %10s%n", "scenario", "B/frame", "us/op(best)", "ops/s", "MB/s");
    }

    interface DecodeOp {
        long run();   // 一次迭代(处理整个语料),返回累计 blackhole
    }

    static void benchDecode(String name, byte[][] corpus) {
        long bytes = 0;
        for (byte[] f : corpus) bytes += f.length;
        bytes /= corpus.length;
        runBench(name, bytes, corpus.length, () -> {
            long bh = 0;
            for (byte[] f : corpus) {
                DecodedPacket p = decoder.decode(f, "bench", 0, 0);
                bh += p.layers().size() + p.protocolPath().length();
            }
            return bh;
        });
    }

    static void benchEncode(String name, Stack[] pool) {
        runBench(name, pool[0].approxBytes(), pool.length, () -> {
            long bh = 0;
            for (Stack s : pool) {
                byte[] out = encoder.encode(s.layers());
                bh += out.length;
            }
            return bh;
        });
    }

    static void benchRoundTrip(String name, FrameKind kind, int listSize) {
        // 往返会改写 POJO,池化轮换
        Stack[] pool = poolOf(kind, listSize, 64);
        runBench(name, pool[0].approxBytes(), pool.length, () -> {
            long bh = 0;
            for (Stack s : pool) {
                byte[] out = encoder.encode(s.layers());
                DecodedPacket p = decoder.decode(out, "bench", 0, 0);
                bh += p.layers().size() + out.length;
            }
            return bh;
        });
    }

    /** unitsPerIter:一次迭代处理的帧数(语料/池大小),ops/s 按单帧归一。 */
    static void runBench(String name, long frameBytes, int unitsPerIter, DecodeOp op) {
        long[] results = new long[(int) MEASURE_ROUNDS];
        try {
            for (int r = 0; r < WARMUP_ROUNDS; r++) timedRound(op, unitsPerIter);
            for (int r = 0; r < MEASURE_ROUNDS; r++) results[r] = timedRound(op, unitsPerIter);
        } catch (Throwable t) {
            System.out.printf("%-28s FAILED: %s%n", name, t);
            t.printStackTrace(System.out);
            return;
        }
        java.util.Arrays.sort(results);
        long best = results[results.length - 1];   // 单元数/秒(升序末位)
        long median = results[results.length / 2];
        System.out.printf("%-28s %10d %12.2f %,12.0f %10.1f   (median %,.0f frames/s)%n",
                name, frameBytes, 1_000_000.0 / best, (double) best, (double) best * frameBytes / 1024 / 1024, (double) median);
    }

    /** 一轮:跑满 ROUND_MS,返回吞吐(单元数/秒,已按 unitsPerIter 归一)。 */
    static long timedRound(DecodeOp op, int unitsPerIter) {
        // 首轮校准:测单次迭代耗时,推算目标迭代数
        long t0 = System.nanoTime();
        long bh = op.run();
        long oneIter = Math.max(System.nanoTime() - t0, 1);
        long iters = Math.max(1, (long) (ROUND_MS * 1_000_000.0 / oneIter * 1.05));
        long sinkLocal = 0;
        t0 = System.nanoTime();
        long done = 0;
        long deadline = t0 + ROUND_MS * 1_000_000L;
        // 先按预算批量跑,再用 deadline 兜底(避免 nanoTime 每迭代开销)
        for (; done < iters; done++) {
            sinkLocal += op.run();
            if ((done & 255) == 0 && System.nanoTime() > deadline) { done++; break; }
        }
        long elapsed = System.nanoTime() - t0;
        sink += bh;   // 校准迭代的 blackhole 也计入
        sink += sinkLocal;
        return (long) (done * (double) unitsPerIter * 1_000_000_000.0 / elapsed);
    }

    // ---------------- 并发 ----------------

    static void benchConcurrentDecode(int threads, byte[][] corpus) throws InterruptedException {
        Map<String, Long> errors = new ConcurrentHashMap<>();
        AtomicLong opsTotal = new AtomicLong();
        long runMs = 3000;
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> ts = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int tid = t;
            Thread th = new Thread(() -> {
                await(start);
                long deadline = System.nanoTime() + runMs * 1_000_000L;
                long ops = 0, bh = 0;
                while (System.nanoTime() < deadline) {
                    try {
                        byte[] f = corpus[(int) ((ops + tid) % corpus.length)];
                        DecodedPacket p = decoder.decode(f, "bench", 0, 0);
                        bh += p.layers().size() + p.protocolPath().length();
                        ops++;
                    } catch (Throwable e) {
                        errors.merge(e.getClass().getSimpleName(), 1L, Long::sum);
                    }
                }
                opsTotal.addAndGet(ops);
                sink += bh;
            }, "bench-" + t);
            th.setDaemon(true);
            th.start();
            ts.add(th);
        }
        // 预热 1s(JIT 编译完成后再发令计时)
        Thread.sleep(1000);
        long t0 = System.nanoTime();
        start.countDown();
        for (Thread th : ts) th.join();
        double sec = (System.nanoTime() - t0) / 1e9;
        double opsPerSec = opsTotal.get() / sec;
        System.out.printf("%-28s threads=%2d  %,14.0f ops/s  errors=%s%n",
                "concurrent decode", threads, opsPerSec,
                errors.isEmpty() ? "none" : errors.toString());
    }

    static void await(CountDownLatch l) {
        try { l.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    static List<Class<?>> scan(String pkg) {
        ClassPathScanningCandidateComponentProvider scanner =
                new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(Protocol.class));
        List<Class<?>> out = new ArrayList<>();
        for (BeanDefinition bd : scanner.findCandidateComponents(pkg)) {
            try {
                out.add(Class.forName(bd.getBeanClassName()));
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException(e);
            }
        }
        return out;
    }
}
