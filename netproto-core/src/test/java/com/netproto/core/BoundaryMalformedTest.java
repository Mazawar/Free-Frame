package com.netproto.core;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 能力边界测试:畸形输入兜底(线上永远会有垃圾字节)。
 * <p>
 * 验收口径:任何畸形输入要么干净失败(带可读原因的 RuntimeException),要么拒绝;
 * 不允许静默错值、不允许长时间挂死。修复后 BitCursor 位/字节读写统一越界报
 * 「bit/byte read past end」(含需求位与剩余量),不再裸 AIOOBE。
 */
@Timeout(10)
class BoundaryMalformedTest {

    // ---- 夹具 ----

    @Data
    @Protocol(id = "b-mal-len")
    static class LenOvershootFrame {
        @ProtocolField(order = 1, size = 16)
        private int len;
        @ProtocolField(order = 2, lengthField = "len", type = FieldType.BYTES)
        private byte[] body = new byte[0];
    }

    @Data
    @Protocol(id = "b-mal-elem")
    static class Elem {
        @ProtocolField(order = 1, size = 16)
        private int v;
    }

    @Data
    @Protocol(id = "b-mal-count")
    static class CountOvershootFrame {
        @ProtocolField(order = 1, size = 32, type = FieldType.UNSIGNED)
        private long count;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "count", elementClass = Elem.class)
        private List<Elem> items = new ArrayList<>();
    }

    @Data
    @Protocol(id = "b-mal-sentinel")
    static class MissingSentinelFrame {
        @ProtocolField(order = 1, sentinel = 0x7E, type = FieldType.BYTES)
        private byte[] data;
    }

    @Data
    @Protocol(id = "b-mal-tlv")
    static class TlvShortValueFrame {
        @ProtocolField(order = 1, type = FieldType.LIST_TLV,
                dispatch = {"1=com.netproto.core.BoundaryMalformedTest$Elem"}, tlvEndMarker = 0xFF)
        private List<Object> items = new ArrayList<>();
    }

    /** 无任何 @ProtocolField 字段的空实体(0 字节元素)。 */
    @Data
    @Protocol(id = "b-mal-empty")
    static class EmptyElem {
    }

    @Data
    @Protocol(id = "b-mal-emptylist")
    static class ZeroByteElementFrame {
        @ProtocolField(order = 1, size = 16)
        private int count;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "count", elementClass = EmptyElem.class)
        private List<EmptyElem> items = new ArrayList<>();
    }

    /** 截断扫描用:多字段 + 位域 + LIST 的中等复杂帧。 */
    @Data
    @Protocol(id = "b-mal-complex")
    static class ComplexFrame {
        @ProtocolField(order = 1, size = 4)
        private int ver;
        @ProtocolField(order = 2, size = 4)
        private int flags;
        @ProtocolField(order = 3, size = 16)
        private int len;
        @ProtocolField(order = 4, size = 32, endian = com.netproto.annotation.Endian.LITTLE)
        private long ts;
        @ProtocolField(order = 5, lengthField = "len", type = FieldType.STRING)
        private String msg = "";
        @ProtocolField(order = 6, size = 8)
        private int crc;
    }

    @Data
    @Protocol(id = "b-mal-negcount")
    static class NegCount8Frame {
        /** byte 型计数字段:0xFF 符号扩展为 -1(int 型字段则零扩展为 255)。 */
        @ProtocolField(order = 1, size = 8)
        private byte count;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "count", elementClass = Elem.class)
        private List<Elem> items = new ArrayList<>();
    }

    // ---- 测试 ----

    /** 长度字段宣称 100,实际只有 4 字节 → 干净失败(长度钳制在读前拒绝:resolved size exceeds remaining)。 */
    @Test
    void lengthOvershootFailsNotCorrupts() {
        ProtocolCodec<LenOvershootFrame> codec = new ProtocolCodec<>(LenOvershootFrame.class);
        byte[] wire = new byte[]{0x00, 100, 0x11, 0x22, 0x33, 0x44};   // len=100, body 仅 4B
        RuntimeException ex = assertThrows(RuntimeException.class, () -> codec.deserialize(wire));
        assertThat(ex.getCause()).hasMessageContaining("exceeds remaining");
    }

    /** 计数字段宣称 100000,实际 1 个元素字节 → 快速失败(不挂死、不先分配大数组)。 */
    @Test
    void countOvershootFailsFast() {
        ProtocolCodec<CountOvershootFrame> codec = new ProtocolCodec<>(CountOvershootFrame.class);
        byte[] wire = {0x00, 0x01, (byte) 0x86, (byte) 0xA0, 0x11, 0x22};
        //   count(4B)=0x000186A0(100000)+ 2B(仅够一个 16bit 元素)
        long start = System.nanoTime();
        assertThrows(RuntimeException.class, () -> codec.deserialize(wire));
        long costMs = (System.nanoTime() - start) / 1_000_000;
        assertThat(costMs).as("应在毫秒级失败,而非逐元素空转").isLessThan(1000);
    }

    /** 终止符缺失 → 干净失败(引擎已有明确报文)。 */
    @Test
    void missingSentinelFailsCleanly() {
        ProtocolCodec<MissingSentinelFrame> codec = new ProtocolCodec<>(MissingSentinelFrame.class);
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> codec.deserialize(new byte[]{0x11, 0x22}));
        assertThat(ex).hasRootCauseMessage("sentinel field data: reached end of data without marker")
                .as("现状:原因在 cause 链上,顶层消息只有类名");
    }

    /** TLV length 宣称 200,实际 5 字节 → 失败(现状:越界)。 */
    @Test
    void tlvShortValueFails() {
        ProtocolCodec<TlvShortValueFrame> codec = new ProtocolCodec<>(TlvShortValueFrame.class);
        byte[] wire = {0x01, 100, 0x11, 0x22, 0x33};   // type=1,len=100,值仅 3B
        assertThrows(RuntimeException.class, () -> codec.deserialize(wire));
    }

    /** 全前缀截断扫描:每个截断点都必须失败,不允许部分解析成功返回。 */
    @Test
    void truncatedAtEveryPositionFails() {
        ProtocolCodec<ComplexFrame> codec = new ProtocolCodec<>(ComplexFrame.class);
        ComplexFrame f = new ComplexFrame();
        f.setVer(1);
        f.setFlags(2);
        f.setLen(5);
        f.setTs(0x0A0B0C0DL);
        f.setMsg("hello");
        f.setCrc(0x5A);
        byte[] full = codec.serialize(f);
        for (int cut = 0; cut < full.length; cut++) {
            byte[] truncated = java.util.Arrays.copyOf(full, cut);
            assertThrows(RuntimeException.class, () -> codec.deserialize(truncated),
                    "截断到 " + cut + " 字节时必须失败");
        }
    }

    /** 空实体元素(0 字节/个)× 255:能正常 round-trip;注意计数无上限时的空转风险(报告项)。 */
    @Test
    void zeroByteElementsSmallCountRoundTrip() {
        ProtocolCodec<ZeroByteElementFrame> codec = new ProtocolCodec<>(ZeroByteElementFrame.class);
        ZeroByteElementFrame f = new ZeroByteElementFrame();
        f.setCount(255);
        f.setItems(new ArrayList<>());
        for (int i = 0; i < 255; i++) {
            f.getItems().add(new EmptyElem());
        }
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(2);   // 只有 count 本身
        ZeroByteElementFrame back = codec.deserialize(wire);
        assertThat(back.getItems()).hasSize(255);
    }

    /**
     * 修复后语义:countField == -1 = null 数组(Kafka 语义)→ 空列表;
     * 小于 -1 的垃圾计数 → 干净报错(此前任何负数都静默空)。
     */
    @Test
    void negativeCountMinusOneIsNullArrayOthersRejected() {
        ProtocolCodec<NegCount8Frame> codec = new ProtocolCodec<>(NegCount8Frame.class);
        // -1 = null 数组:空列表(设计语义)
        NegCount8Frame nullArray = codec.deserialize(new byte[]{(byte) 0xFF});
        assertThat(nullArray.getCount()).isEqualTo((byte) -1);
        assertThat(nullArray.getItems()).isEmpty();
        // -2 = 垃圾:拒绝
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> codec.deserialize(new byte[]{(byte) 0xFE}));
        assertThat(ex.getCause()).hasMessageContaining("invalid (must be >= 0");
    }
}
