package com.netproto.core;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 能力边界测试:位级对齐。
 * <p>
 * 引擎 BitCursor 为 MSB 优先、允许字段跨字节;readBits 对任意对齐正确。
 * readBytes/writeBytes(服务于 BYTES/STRING/NESTED)曾只支持字节对齐——解码侧非对齐
 * 按物理字节直取(静默错位)、编码侧直接拒绝(不对称)。已修复为位级位移读写,
 * 本组测试钉死非对齐 BYTES 的正确 round-trip 与手算位布局。
 */
class BoundaryBitAlignmentTest {

    // ---- 夹具 ----

    /** 3bit 标志 + 16bit BYTES 字段:BYTES 起点在 bit3,非字节对齐。 */
    @Data
    @Protocol(id = "b-align-bytes")
    static class UnalignedBytesFrame {
        @ProtocolField(order = 1, size = 3)
        private int flag;
        @ProtocolField(order = 2, size = 16, type = FieldType.BYTES)
        private byte[] data;
    }

    /** 3bit + 13bit + 16bit:全位字段(无 BYTES),跨字节组合应完全正确。 */
    @Data
    @Protocol(id = "b-align-bits")
    static class AllBitfieldsFrame {
        @ProtocolField(order = 1, size = 3)
        private int a;
        @ProtocolField(order = 2, size = 13)
        private int b;
        @ProtocolField(order = 3, size = 16)
        private int c;
    }

    /** 24bit 整数字段横跨 3 字节(单字段跨字节,正例)。 */
    @Data
    @Protocol(id = "b-align-cross")
    static class CrossByteFieldFrame {
        @ProtocolField(order = 1, size = 4)
        private int hi;
        @ProtocolField(order = 2, size = 24)
        private int wide;
        @ProtocolField(order = 3, size = 4)
        private int lo;
    }

    /** lengthUnit=BITS 引出非整字节 BYTES(1.5 字节)。 */
    @Data
    @Protocol(id = "b-align-bitsunit")
    static class BitUnitLengthFrame {
        @ProtocolField(order = 1, size = 8)
        private int bitLen;
        @ProtocolField(order = 2, lengthField = "bitLen", lengthUnit = LengthUnit.BITS, type = FieldType.BYTES)
        private byte[] data;
    }

    // ---- 测试 ----

    @Test
    void allBitfieldCombinationRoundTrips() {
        ProtocolCodec<AllBitfieldsFrame> codec = new ProtocolCodec<>(AllBitfieldsFrame.class);
        AllBitfieldsFrame f = new AllBitfieldsFrame();
        f.setA(0b101);
        f.setB(0x1234 & 0x1FFF);
        f.setC(0xABCD);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(4);
        AllBitfieldsFrame back = codec.deserialize(wire);
        assertThat(back.getA()).isEqualTo(f.getA());
        assertThat(back.getB()).isEqualTo(f.getB());
        assertThat(back.getC()).isEqualTo(f.getC());
    }

    @Test
    void singleFieldCrossesBytesCorrectly() {
        ProtocolCodec<CrossByteFieldFrame> codec = new ProtocolCodec<>(CrossByteFieldFrame.class);
        CrossByteFieldFrame f = new CrossByteFieldFrame();
        f.setHi(0xA);
        f.setWide(0xABCDEF);
        f.setLo(0x5);
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(
                (byte) 0xAA, (byte) 0xBC, (byte) 0xDE, (byte) 0xF5);
        CrossByteFieldFrame back = codec.deserialize(wire);
        assertThat(back.getWide()).isEqualTo(0xABCDEF);
        assertThat(back.getHi()).isEqualTo(0xA);
        assertThat(back.getLo()).isEqualTo(0x5);
    }

    /**
     * 非对齐 BYTES 读写位级正确(修复后):flag(3bit)=101 + data(16bit)=0x1234
     * → 线路位 101 00010010 001101 00 000 → A2 46 80,round-trip 无损。
     */
    @Test
    void unalignedBytesRoundTripBitAccurate() {
        ProtocolCodec<UnalignedBytesFrame> codec = new ProtocolCodec<>(UnalignedBytesFrame.class);
        UnalignedBytesFrame f = new UnalignedBytesFrame();
        f.setFlag(0b101);
        f.setData(new byte[]{0x12, 0x34});
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly((byte) 0xA2, 0x46, (byte) 0x80);

        UnalignedBytesFrame back = codec.deserialize(wire);
        assertThat(back.getFlag()).isEqualTo(0b101);
        assertThat(back.getData()).containsExactly(0x12, 0x34);   // 不再含 flag 位、不再丢尾部位
    }

    /** lengthUnit=BITS 且位数非 8 的倍数 → 解码 readBytes 拒绝(干净失败)。 */
    @Test
    void bitUnitNonByteMultipleRejected() {
        ProtocolCodec<BitUnitLengthFrame> codec = new ProtocolCodec<>(BitUnitLengthFrame.class);
        byte[] wire = new byte[]{20, 0x11, 0x22, 0x33}; // 20bit = 2.5 字节
        RuntimeException ex = assertThrows(RuntimeException.class, () -> codec.deserialize(wire));
        assertThat(ex.getCause()).hasMessageContaining("multiple of 8");
    }

    /** lengthUnit=BITS 且为 8 的倍数 → 正常(位单位长度可用)。 */
    @Test
    void bitUnitByteMultipleWorks() {
        ProtocolCodec<BitUnitLengthFrame> codec = new ProtocolCodec<>(BitUnitLengthFrame.class);
        BitUnitLengthFrame f = new BitUnitLengthFrame();
        f.setBitLen(16);
        f.setData(new byte[]{0x55, (byte) 0xAA});
        byte[] wire = codec.serialize(f);
        BitUnitLengthFrame back = codec.deserialize(wire);
        assertThat(back.getData()).containsExactly(0x55, (byte) 0xAA);
    }
}
