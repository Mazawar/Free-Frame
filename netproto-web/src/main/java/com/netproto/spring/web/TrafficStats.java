package com.netproto.spring.web;

import com.netproto.spring.capture.FrameSummary;
import com.netproto.stack.ProtocolRegistry;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 流量统计聚合:会话(方向无关端点对)+ 协议分布 + 吞吐时间线。
 * 纯 {@link FrameSummary} 摘要聚合,不触原始字节、不重解码 —— 10 万帧也是毫秒级。
 * <p>
 * 会话键:有传输层端口用「地址:端口」对(双向归一,取字典序),否则退化为地址对(MAC 对)。
 * 协议归属取帧的最深协议(Wireshark 协议列语义)。
 */
final class TrafficStats {

    private TrafficStats() {}

    /** 会话表最多条数(按字节降序截取,防端点爆炸刷屏)。 */
    static final int MAX_CONVERSATIONS = 100;
    /** 吞吐时间线分桶数。 */
    static final int BUCKETS = 120;

    private static final class Conv {
        final String key;
        final String srcHost, dstHost;
        final Integer srcPort, dstPort;
        final boolean withPorts;
        int frames;
        long bytes, first, last;
        final Map<String, Integer> protos = new HashMap<>();

        Conv(String key, String srcHost, String dstHost, Integer srcPort, Integer dstPort, boolean withPorts) {
            this.key = key;
            this.srcHost = srcHost;
            this.dstHost = dstHost;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.withPorts = withPorts;
        }
    }

    /** frames 须为旧→新。 */
    static Map<String, Object> of(List<FrameSummary> frames, ProtocolRegistry registry) {
        long totalFrames = 0, totalBytes = 0;
        long tMin = Long.MAX_VALUE, tMax = Long.MIN_VALUE;
        for (FrameSummary f : frames) {
            totalFrames++;
            totalBytes += f.len();
            tMin = Math.min(tMin, f.ts());
            tMax = Math.max(tMax, f.ts());
        }
        Map<String, Conv> convs = new HashMap<>();
        Map<String, long[]> protos = new LinkedHashMap<>();   // id → {frames, bytes}
        int[] bFrames = new int[BUCKETS];
        long[] bBytes = new long[BUCKETS];
        long bucketMs = 1;
        if (totalFrames > 0) {
            bucketMs = Math.max(1, (tMax - tMin + BUCKETS - 1) / BUCKETS);
        }
        for (FrameSummary f : frames) {
            long[] p = protos.computeIfAbsent(f.protoId(), k -> new long[2]);
            p[0]++;
            p[1] += f.len();
            boolean withPorts = f.srcPort() != null && f.dstPort() != null;
            String a = withPorts ? f.src() + ":" + f.srcPort() : f.src();
            String b = withPorts ? f.dst() + ":" + f.dstPort() : f.dst();
            String key = a.compareTo(b) <= 0 ? a + " ⇄ " + b : b + " ⇄ " + a;
            Conv c = convs.computeIfAbsent(key,
                    k -> new Conv(k, f.src(), f.dst(), f.srcPort(), f.dstPort(), withPorts));
            c.frames++;
            c.bytes += f.len();
            c.first = c.first == 0 ? f.ts() : Math.min(c.first, f.ts());
            c.last = Math.max(c.last, f.ts());
            c.protos.merge(f.protoId(), 1, Integer::sum);
            int idx = (int) Math.min(BUCKETS - 1, (f.ts() - tMin) / bucketMs);
            bFrames[idx]++;
            bBytes[idx] += f.len();
        }

        List<Map<String, Object>> convList = new ArrayList<>();
        convs.values().stream()
                .sorted(Comparator.comparingLong((Conv c) -> c.bytes).reversed())
                .limit(MAX_CONVERSATIONS)
                .forEach(c -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("key", c.key);
                    m.put("srcHost", c.srcHost);
                    m.put("dstHost", c.dstHost);
                    m.put("srcPort", c.srcPort);
                    m.put("dstPort", c.dstPort);
                    m.put("withPorts", c.withPorts);
                    m.put("frames", c.frames);
                    m.put("bytes", c.bytes);
                    m.put("first", c.first);
                    m.put("last", c.last);
                    m.put("rateBps", c.last > c.first ? c.bytes * 1000 / (c.last - c.first) : 0);
                    // 协议标签取该会话占比最高的(最深协议;混杂会话显示主导协议)
                    String dominant = c.protos.entrySet().stream()
                            .max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse("-");
                    m.put("proto", dominant);
                    m.put("protoName", protoName(registry, dominant));
                    convList.add(m);
                });

        List<Map<String, Object>> protoList = new ArrayList<>();
        protos.entrySet().stream()
                .sorted(Comparator.comparingLong((Map.Entry<String, long[]> e) -> e.getValue()[1]).reversed())
                .limit(24)
                .forEach(e -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", e.getKey());
                    m.put("name", protoName(registry, e.getKey()));
                    m.put("frames", e.getValue()[0]);
                    m.put("bytes", e.getValue()[1]);
                    protoList.add(m);
                });

        List<Map<String, Object>> buckets = new ArrayList<>(BUCKETS);
        for (int i = 0; i < BUCKETS; i++) {
            if (bFrames[i] == 0) {
                continue;   // 稀疏:只出非空桶,前端按 t0 定位
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("t0", tMin == Long.MAX_VALUE ? 0 : tMin + i * bucketMs);
            m.put("frames", bFrames[i]);
            m.put("bytes", bBytes[i]);
            buckets.add(m);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> window = new LinkedHashMap<>();
        window.put("frames", totalFrames);
        window.put("bytes", totalBytes);
        window.put("from", tMin == Long.MAX_VALUE ? 0 : tMin);
        window.put("to", tMax == Long.MIN_VALUE ? 0 : tMax);
        out.put("window", window);
        out.put("conversations", convList);
        out.put("protocols", protoList);
        out.put("timeline", Map.of("bucketMs", bucketMs, "buckets", buckets));
        return out;
    }

    private static String protoName(ProtocolRegistry registry, String id) {
        ProtocolRegistry.Entry e = registry.get(id);
        return e != null ? e.name() : id;
    }
}
