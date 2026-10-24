package com.netproto.core;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 2026-10-24 全面审计后的加固回归:此前 LIST 的 sentinel/sentinelOn 循环缺零进展保护
 * (可零消耗元素 → 纯死循环,连异常都不抛)、count 无元素上限(恶意 count × 每元素分配 →
 * OOM 是 Error 绕过 catch(Exception))、NESTED 递归无深度上限(SOE 同样绕过)、
 * 超界 lengthField 经 (int) 截断可变负数/0。本类逐条锁死这些形态。
 */
@Timeout(30)
class BoundaryHardeningTest {

    // ---- 夹具 ----

    /** 唯一字段被常量假 presentIf 跳过 → 元素永远消耗 0 位(sentinel 循环的死循环原料)。 */
    @Data
    @Protocol(id = "bh-skip-elem")
    static class SkippedElem {
        @ProtocolField(order = 1, size = 8, presentIf = "0")
        private int v;
    }

    @Data
    @Protocol(id = "bh-sentinel")
    static class SentinelZeroProgressFrame {
        @ProtocolField(order = 1, sentinel = 0x7E, type = FieldType.LIST, elementClass = SkippedElem.class)
        private List<SkippedElem> items = new ArrayList<>();
    }

    @Data
    @Protocol(id = "bh-sentinelon")
    static class SentinelOnZeroProgressFrame {
        @ProtocolField(order = 1, type = FieldType.LIST, elementClass = SkippedElem.class,
                sentinelOn = "v", sentinelValue = 0x1F)
        private List<SkippedElem> items = new ArrayList<>();
    }

    /** 8 位(单字节)元素:数据能喂饱 100 万+ 个 → 触发元素数上限(而非 OOM)。
     *  注:LIST 元素解码走 byteOffset/remainingBytes,元素起点须字节对齐,1 位元素不可用。 */
    @Data
    @Protocol(id = "bh-bit-elem")
    static class BitElem {
        @ProtocolField(order = 1, size = 8)
        private int b;
    }

    @Data
    @Protocol(id = "bh-bigcount")
    static class HugeCountFrame {
        @ProtocolField(order = 1, size = 32, type = FieldType.UNSIGNED)
        private long count;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "count", elementClass = BitElem.class)
        private List<BitElem> bits = new ArrayList<>();
    }

    /** 自引用 NESTED(吃剩余字节):任意小帧即可叠任意深度。 */
    @Data
    @Protocol(id = "bh-node")
    static class Node {
        @ProtocolField(order = 1, size = 8)
        private int tag;
        @ProtocolField(order = 2, type = FieldType.NESTED)
        private Node child;
    }

    /** 32 位 lengthField × 8 溢出 (int) 的两个截断形态。 */
    @Data
    @Protocol(id = "bh-len32")
    static class Len32Frame {
        @ProtocolField(order = 1, size = 32, type = FieldType.UNSIGNED)
        private long len;
        @ProtocolField(order = 2, lengthField = "len", type = FieldType.BYTES)
        private byte[] body = new byte[0];
    }

    /** 并发首刷 NESTED 缓存用(见 nestedCacheConcurrentFirstTouch)。 */
    @Data
    @Protocol(id = "bh-inner")
    static class Inner {
        @ProtocolField(order = 1, size = 16)
        private int x;
    }

    @Data
    @Protocol(id = "bh-outer")
    static class Outer {
        @ProtocolField(order = 1, size = 8)
        private int a;
        @ProtocolField(order = 2, type = FieldType.NESTED)
        private Inner inner;
    }

    // ---- sentinel 循环零进展:可零消耗元素必须立即失败,不允许挂死 ----

    @Test
    void sentinelListZeroProgressElementFailsFast() {
        ProtocolCodec<SentinelZeroProgressFrame> codec = new ProtocolCodec<>(SentinelZeroProgressFrame.class);
        // 0x11 != 0x7E(标记),元素消耗 0 位 → 修复前此处是 100% CPU 死循环
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> codec.deserialize(new byte[]{0x11, 0x22}));
        assertThat(ex).hasRootCauseMessage("LIST field 'items': element consumed 0 bits"
                + " (empty element or all fields skipped by presentIf?)"
                + " — cursor cannot advance, aborting decode");
    }

    @Test
    void sentinelOnListZeroProgressElementFailsFast() {
        ProtocolCodec<SentinelOnZeroProgressFrame> codec = new ProtocolCodec<>(SentinelOnZeroProgressFrame.class);
        // peek 8 位 = 0x11 != 0x1F(终止值),元素消耗 0 位 → 同上
        assertThrows(RuntimeException.class, () -> codec.deserialize(new byte[]{0x11, 0x22}));
    }

    // ---- count × 元素数上限:数据喂得饱百万级元素也必须在上限处干净失败 ----

    @Test
    void hugeCountHitsElementCapInsteadOfOom() {
        ProtocolCodec<HugeCountFrame> codec = new ProtocolCodec<>(HugeCountFrame.class);
        byte[] wire = new byte[4 + 1_200_000];   // count + 120 万字节(每元素 1B)> 100 万上限
        wire[0] = 0x7F;                          // count = 0x7FFFFFFF(2^31-1)
        wire[1] = (byte) 0xFF;
        wire[2] = (byte) 0xFF;
        wire[3] = (byte) 0xFF;
        long start = System.nanoTime();
        RuntimeException ex = assertThrows(RuntimeException.class, () -> codec.deserialize(wire));
        long costMs = (System.nanoTime() - start) / 1_000_000;
        assertThat(ex).hasRootCauseMessage("LIST field 'bits': exceeds 1048576 elements"
                + " (malformed count or missing sentinel?)");
        assertThat(costMs).as("上限截断应在百毫秒级,而非堆增长到 OOM").isLessThan(2000);
    }

    // ---- 递归深度上限:自引用协议 + 小帧 → 干净 ISE,不允许 StackOverflowError ----

    @Test
    void selfNestedDepthCappedNotStackOverflow() {
        ProtocolCodec<Node> codec = new ProtocolCodec<>(Node.class);
        byte[] wire = new byte[100];   // 每层 1 字节 tag + 剩余全给 child:100 字节足以叠 64+ 层
        java.util.Arrays.fill(wire, (byte) 0x01);
        RuntimeException ex = assertThrows(RuntimeException.class, () -> codec.deserialize(wire));
        assertThat(ex).hasRootCauseMessage("protocol nesting deeper than 64"
                + " (cyclic protocol definition or malformed frame?)");
    }

    // ---- 超界 lengthField:截断为负(原 NegativeArraySizeException)/截断为 0(原静默空读)----

    @Test
    void lengthFieldOvershootRejectedBeforeIntTruncation() {
        ProtocolCodec<Len32Frame> codec = new ProtocolCodec<>(Len32Frame.class);
        // 0x1FFFFFFF × 8 = 0xFFFFFFF8 → (int) 截断为 -8(原:NegativeArraySizeException)
        byte[] negTrunc = {0x1F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x11, 0x22};
        RuntimeException ex1 = assertThrows(RuntimeException.class, () -> codec.deserialize(negTrunc));
        assertThat(ex1.getCause()).hasMessageContaining("exceeds remaining");

        // 0x20000000 × 8 = 2^32 → (int) 截断为 0(原:静默读空、解析结果错误)
        byte[] zeroTrunc = {0x20, 0x00, 0x00, 0x00, 0x11, 0x22};
        RuntimeException ex2 = assertThrows(RuntimeException.class, () -> codec.deserialize(zeroTrunc));
        assertThat(ex2.getCause()).hasMessageContaining("exceeds remaining");
    }

    // ---- NESTED_CACHE 并发首刷:多线程同时首次解码同一嵌套类型不得损坏(原裸 HashMap)----

    @Test
    void nestedCacheConcurrentFirstTouch() throws Exception {
        ProtocolCodec<Outer> codec = new ProtocolCodec<>(Outer.class);
        byte[] wire = {0x0A, 0x02, 0x03};   // a=0x0A, inner.x=0x0203
        int threads = 8;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger failures = new AtomicInteger();
        List<Thread> hammer = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            Thread th = new Thread(() -> {
                try {
                    ready.countDown();
                    go.await();
                    for (int i = 0; i < 300; i++) {
                        Outer o = codec.deserialize(wire);
                        if (o.getA() != 0x0A || o.getInner().getX() != 0x0203) {
                            failures.incrementAndGet();
                        }
                    }
                } catch (Throwable e) {
                    failures.incrementAndGet();
                }
            }, "bh-hammer-" + t);
            hammer.add(th);
            th.start();
        }
        ready.await();
        go.countDown();   // 8 线程同拍首刷(Inner 尚未进缓存)
        for (Thread th : hammer) {
            th.join(5000);
        }
        assertThat(failures.get()).as("并发首刷 + 解码值必须全对").isZero();
    }
}
