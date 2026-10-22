package com.netproto.core;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 能力边界测试:极值与零值。
 * <ul>
 *   <li>UNSIGNED 63bit 上限 / INT 负数补码 round-trip;</li>
 *   <li>BCD 16 位数字上限(long 装载);</li>
 *   <li>空集合/空字符串/空载荷的编码与回填;</li>
 *   <li>非 UTF-8 字符集(GBK,国内表计/终端常态);</li>
 *   <li>128bit 定长字段(UUID/EUI-64 扩展);</li>
 *   <li>size=0 / size=65 的注册期缺口(现状:注册放行,运行期才炸 —— 报告项)。</li>
 * </ul>
 */
class BoundaryExtremeValuesTest {

    // ---- 夹具 ----

    @Data
    @Protocol(id = "b-ext-int")
    static class ExtIntFrame {
        @ProtocolField(order = 1, size = 63, type = FieldType.UNSIGNED)
        private long maxU63;
        @ProtocolField(order = 2, size = 8)
        private byte minI8;
        @ProtocolField(order = 3, size = 32)
        private int minusOne;
        @ProtocolField(order = 4, size = 32)
        private float f32 = -0.25f;
        @ProtocolField(order = 5, size = 64)
        private double f64 = 1e300;
    }

    @Data
    @Protocol(id = "b-ext-bcd")
    static class ExtBcdFrame {
        @ProtocolField(order = 1, size = 64, type = FieldType.BCD)
        private long digits16;
    }

    @Data
    @Protocol(id = "b-ext-empty")
    static class EmptyThingsFrame {
        @ProtocolField(order = 1, size = 8)
        private int count;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "count", elementClass = U16.class)
        private java.util.List<U16> items = new ArrayList<>();
        @ProtocolField(order = 3, size = 8)
        private int strLen;
        @ProtocolField(order = 4, type = FieldType.STRING, lengthField = "strLen")
        private String text = "";
    }

    @Data
    @Protocol(id = "b-ext-u16")
    static class U16 {
        @ProtocolField(order = 1, size = 16)
        private int v;
    }

    @Data
    @Protocol(id = "b-ext-gbk")
    static class GbkFrame {
        @ProtocolField(order = 1, size = 8)
        private int len;
        @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "len", charset = "GBK")
        private String devName;
    }

    @Data
    @Protocol(id = "b-ext-uuid")
    static class UuidFrame {
        @ProtocolField(order = 1, size = 128, type = FieldType.BYTES)
        private byte[] uuid;
    }

    @Data
    @Protocol(id = "b-ext-size0")
    static class SizeZeroFrame {
        @ProtocolField(order = 1, size = 0)
        private int v;
    }

    @Data
    @Protocol(id = "b-ext-size65")
    static class Size65Frame {
        @ProtocolField(order = 1, size = 65)
        private long v;
    }

    // ---- 测试 ----

    @Test
    void integerExtremesRoundTrip() {
        ProtocolCodec<ExtIntFrame> codec = new ProtocolCodec<>(ExtIntFrame.class);
        ExtIntFrame f = new ExtIntFrame();
        f.setMaxU63(Long.MAX_VALUE);          // 2^63-1
        f.setMinI8((byte) -128);
        f.setMinusOne(-1);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize((63 + 8 + 32 + 32 + 64 + 7) / 8);   // 26B
        ExtIntFrame back = codec.deserialize(wire);
        assertThat(back.getMaxU63()).isEqualTo(Long.MAX_VALUE);
        assertThat(back.getMinI8()).isEqualTo((byte) -128);
        assertThat(back.getMinusOne()).isEqualTo(-1);
        assertThat(back.getF32()).isEqualTo(-0.25f);
        assertThat(back.getF64()).isEqualTo(1e300);
    }

    @Test
    void bcd16DigitsRoundTrip() {
        ProtocolCodec<ExtBcdFrame> codec = new ProtocolCodec<>(ExtBcdFrame.class);
        ExtBcdFrame f = new ExtBcdFrame();
        f.setDigits16(9999999999999999L);
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(
                (byte) 0x99, (byte) 0x99, (byte) 0x99, (byte) 0x99,
                (byte) 0x99, (byte) 0x99, (byte) 0x99, (byte) 0x99);
        assertThat(codec.deserialize(wire).getDigits16()).isEqualTo(9999999999999999L);
    }

    /** 空集合(计数自动回填 0)+ 空字符串。 */
    @Test
    void emptyListAndStringEncodeToZero() {
        ProtocolCodec<EmptyThingsFrame> codec = new ProtocolCodec<>(EmptyThingsFrame.class);
        EmptyThingsFrame f = new EmptyThingsFrame();
        f.setItems(new ArrayList<>());
        f.setText("");
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(0, 0);   // count=0(自动回填)+ strLen=0
    }

    @Test
    void gbkCharsetRoundTrip() {
        ProtocolCodec<GbkFrame> codec = new ProtocolCodec<>(GbkFrame.class);
        GbkFrame f = new GbkFrame();
        f.setDevName("终端01");   // GBK:2 汉字×2B + 2 ASCII = 6 字节
        f.setLen(6);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(7);
        GbkFrame back = codec.deserialize(wire);
        assertThat(back.getDevName()).isEqualTo("终端01");
    }

    @Test
    void uuid128BitFieldRoundTrip() {
        ProtocolCodec<UuidFrame> codec = new ProtocolCodec<>(UuidFrame.class);
        UuidFrame f = new UuidFrame();
        byte[] uuid = new byte[16];
        for (int i = 0; i < 16; i++) {
            uuid[i] = (byte) (i * 0x11);
        }
        f.setUuid(uuid);
        assertThat(codec.serialize(f)).hasSize(16);
        assertThat(codec.deserialize(codec.serialize(f)).getUuid()).containsExactly(uuid);
    }

    /** 修复后:size=0 注册期直接拒绝(此前运行期才报「cannot resolve size」)。 */
    @Test
    void sizeZeroRejectedAtRegistration() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new ProtocolCodec<>(SizeZeroFrame.class));
        assertThat(ex).hasMessageContaining("invalid size 0");
    }

    /** 修复后:数值字段 size>64 注册期直接拒绝(此前运行期 BitCursor 才拒绝)。 */
    @Test
    void size65RejectedAtRegistration() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new ProtocolCodec<>(Size65Frame.class));
        assertThat(ex).hasMessageContaining("requires size 1..64");
    }
}
