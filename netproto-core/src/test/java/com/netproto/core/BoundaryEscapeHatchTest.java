package com.netproto.core;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 能力边界测试:逃生舱充分性(声明式确实做不了的,逃生舱能否接住)。
 * <ul>
 *   <li>BER 长形式长度(0x81/0x82 前缀,DER/ASN.1/EMV)—— L2 字段级 FieldCodec;</li>
 *   <li>PPP 字节转义(0x7D XOR 0x20,含 0x7E 帧界)—— 整帧变换,须 L3 PacketCodec。</li>
 * </ul>
 * 结论驱动:若这两类能接住,L2/L3 分层即覆盖「变长长度编码」与「字节填充」两大不可声明族。
 */
class BoundaryEscapeHatchTest {

    // ---- L2:BER 长形式长度 ----

    /** BER definite-form 长度:短形式 1B(<128);长形式 0x8N + N 字节 BE。 */
    public static class BerLengthCodec implements FieldCodec<Long> {
        @Override
        public Long read(BitCursor cursor, FieldContext ctx, int remainingBytes) {
            int first = (int) cursor.readBits(8) & 0xFF;
            if ((first & 0x80) == 0) {
                return (long) first;
            }
            int n = first & 0x7F;
            if (n == 0 || n > 8) {
                throw new IllegalStateException("BER indefinite/huge length unsupported: 0x"
                        + Integer.toHexString(first));
            }
            return cursor.readBits(n * 8);
        }

        @Override
        public void write(BitCursor cursor, FieldContext ctx, Long value) {
            long v = value == null ? 0 : value;
            if (v < 128) {
                cursor.writeBits(v, 8);
                return;
            }
            int n = (Long.numberOfTrailingZeros(Long.highestOneBit(v)) + 8) / 8;
            cursor.writeBits(0x80L | n, 8);
            cursor.writeBits(v, n * 8);
        }

        @Override
        public long sizeOf(Long value) {
            long v = value == null ? 0 : value;
            if (v < 128) {
                return 8;
            }
            int n = (Long.numberOfTrailingZeros(Long.highestOneBit(v)) + 8) / 8;
            return 8L * (1 + n);
        }
    }

    @Data
    @Protocol(id = "b-ber-tlv")
    static class BerTlvFrame {
        @ProtocolField(order = 1, size = 8)
        private int tag;
        @ProtocolField(order = 2, custom = BerLengthCodec.class)
        private Long len;
        @ProtocolField(order = 3, lengthField = "len", type = FieldType.BYTES)
        private byte[] value = new byte[0];
    }

    // ---- L3:PPP 字节转义 ----

    @Data
    @Protocol(id = "b-ppp-inner")
    static class PppInner {
        @ProtocolField(order = 1, size = 8)
        private int addr = 0xFF;
        @ProtocolField(order = 2, size = 8)
        private int ctrl = 0x03;
        @ProtocolField(order = 3, size = 16)
        private int protocol = 0x0021;
        @ProtocolField(order = 4, size = 16)
        private int fcs;
        @ProtocolField(order = 5, sentinel = 0, type = FieldType.BYTES)
        private byte[] info;
    }

    /** PPP 式帧:0x7E 起止 + 0x7D XOR 0x20 转义;整帧变换必须 L3。 */
    public static class StuffedFrameCodec implements PacketCodec<PppInner> {
        private final ProtocolCodec<PppInner> inner = new ProtocolCodec<>(PppInner.class);

        @Override
        public PppInner decode(byte[] data, int offset, int length) {
            if (length < 2 || data[offset] != 0x7E || data[offset + length - 1] != 0x7E) {
                throw new IllegalArgumentException("missing PPP flag 0x7E");
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            for (int i = offset + 1; i < offset + length - 1; i++) {
                int b = data[i] & 0xFF;
                if (b == 0x7D) {
                    i++;
                    bos.write((data[i] & 0xFF) ^ 0x20);
                } else {
                    bos.write(b);
                }
            }
            return inner.decode(bos.toByteArray(), 0, bos.size());
        }

        @Override
        public byte[] encode(PppInner packet) {
            byte[] raw = inner.encode(packet);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(0x7E);
            for (byte b : raw) {
                int v = b & 0xFF;
                if (v == 0x7E || v == 0x7D) {
                    bos.write(0x7D);
                    bos.write(v ^ 0x20);
                } else {
                    bos.write(v);
                }
            }
            bos.write(0x7E);
            return bos.toByteArray();
        }

        @Override
        public int headerBytes() {
            return -1;   // 叶子协议:不参与子层分派
        }
    }

    // ---- 测试 ----

    /** DER 教科书向量:82 01 2C + 300 字节。 */
    @Test
    void berLongFormLengthRoundTrip() {
        ProtocolCodec<BerTlvFrame> codec = new ProtocolCodec<>(BerTlvFrame.class);
        BerTlvFrame f = new BerTlvFrame();
        f.setTag(0x04);
        f.setLen(300L);
        byte[] value = new byte[300];
        for (int i = 0; i < value.length; i++) {
            value[i] = (byte) i;
        }
        f.setValue(value);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(4 + 300);
        assertThat(wire).containsSubsequence((byte) 0x04, (byte) 0x82, (byte) 0x01, (byte) 0x2C);

        BerTlvFrame back = codec.deserialize(wire);
        assertThat(back.getLen()).isEqualTo(300L);
        assertThat(back.getValue()).containsExactly(value);
    }

    @Test
    void berShortAndMediumFormsRoundTrip() {
        ProtocolCodec<BerTlvFrame> codec = new ProtocolCodec<>(BerTlvFrame.class);
        for (long len : new long[]{5, 127, 128, 255, 256}) {
            BerTlvFrame f = new BerTlvFrame();
            f.setTag(0x30);
            f.setLen(len);
            f.setValue(new byte[(int) len]);
            byte[] wire = codec.serialize(f);
            BerTlvFrame back = codec.deserialize(wire);
            assertThat(back.getLen()).as("len=%d", len).isEqualTo(len);
            assertThat(wire).as("len=%d", len).hasSize((int) len + (len < 128 ? 2 : len < 256 ? 3 : 4));
        }
    }

    /** BER indefinite form(0x80)是 SNMP/DER 禁用形态:L2 明确拒绝。 */
    @Test
    void berIndefiniteLengthRejected() {
        ProtocolCodec<BerTlvFrame> codec = new ProtocolCodec<>(BerTlvFrame.class);
        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> codec.deserialize(new byte[]{0x04, (byte) 0x80}));
        assertThat(ex.getCause()).hasMessageContaining("indefinite");
    }

    /** PPP 转义:载荷含 0x7E/0x7D 时 round-trip 仍正确(escape 后帧界不冲突)。 */
    @Test
    void pppByteStuffingRoundTrip() {
        StuffedFrameCodec codec = new StuffedFrameCodec();
        PppInner inner = new PppInner();
        inner.setFcs(0xABCD);
        inner.setInfo(new byte[]{0x55, 0x7E, 0x7D, 0x11, 0x00});
        byte[] wire = codec.encode(inner);
        // 0x7E → 7D 5E;0x7D → 7D 5D;0x00 为 sentinel 终止符
        assertThat(wire).containsSubsequence(
                (byte) 0x7D, (byte) 0x5E,   // 7E 转义
                (byte) 0x7D, (byte) 0x5D);  // 7D 转义
        assertThat(wire[0]).isEqualTo((byte) 0x7E);
        assertThat(wire[wire.length - 1]).isEqualTo((byte) 0x7E);

        PppInner back = codec.decode(wire, 0, wire.length);
        assertThat(back.getInfo()).containsExactly(0x55, 0x7E, 0x7D, 0x11);
        assertThat(back.getFcs()).isEqualTo(0xABCD);
    }
}
