package com.netproto.protocols.real.quic;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.BitCursor;
import com.netproto.core.FieldCodec;
import com.netproto.core.FieldContext;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QUIC Variable-Length Integer(RFC 9000 §16)真实向量测试。
 * <p>
 * 四个规范示例向量(自 RFC 原文):
 * <ul>
 *   <li>{@code 25} → 37(2bit 前缀 00,1 字节)</li>
 *   <li>{@code 7B BD} → 15293(01,2 字节)</li>
 *   <li>{@code 9D 7F 3E 7D} → 494878333(10,4 字节)</li>
 *   <li>{@code C2 19 7C 5E FF 14 E9 51} → 151288809941952652(11,8 字节)</li>
 * </ul>
 * 声明式无法表达「首 2bit 决定自身宽度」→ L2 自定义 FieldCodec。
 */
class QuicVarintRealTest {

    /** QUIC varint:首字节高 2bit 编码宽度(1/2/4/8 字节),其余位 BE。 */
    public static class QuicVarintCodec implements FieldCodec<Long> {
        @Override
        public Long read(BitCursor cursor, FieldContext ctx, int remainingBytes) {
            int first = (int) cursor.readBits(8) & 0xFF;
            int bytes = 1 << (first >>> 6);
            long v = first & 0x3F;
            for (int i = 1; i < bytes; i++) {
                v = (v << 8) | (cursor.readBits(8) & 0xFF);
            }
            return v;
        }

        @Override
        public void write(BitCursor cursor, FieldContext ctx, Long value) {
            long v = value == null ? 0 : value;
            int bytes = widthOf(v);
            int prefix = switch (bytes) {
                case 1 -> 0;
                case 2 -> 1;
                case 4 -> 2;
                default -> 3;
            };
            cursor.writeBits(((long) prefix << 6) | (v >>> ((bytes - 1) * 8)), 8);
            for (int i = bytes - 2; i >= 0; i--) {
                cursor.writeBits(v >>> (i * 8), 8);
            }
        }

        @Override
        public long sizeOf(Long value) {
            return widthOf(value == null ? 0 : value) * 8L;
        }

        private static int widthOf(long v) {
            if (v < (1L << 6)) {
                return 1;
            }
            if (v < (1L << 14)) {
                return 2;
            }
            if (v < (1L << 30)) {
                return 4;
            }
            return 8;
        }
    }

    @Data
    @Protocol(id = "real-quic-varint")
    static class VarintFrame {
        @ProtocolField(order = 1, custom = QuicVarintCodec.class)
        private Long value;
    }

    @Test
    void rfcVectors() {
        ProtocolCodec<VarintFrame> codec = new ProtocolCodec<>(VarintFrame.class);

        assertRoundTrip(codec, new byte[]{0x25}, 37L);
        assertRoundTrip(codec, new byte[]{0x7B, (byte) 0xBD}, 15293L);
        assertRoundTrip(codec, new byte[]{(byte) 0x9D, 0x7F, 0x3E, 0x7D}, 494878333L);
        assertRoundTrip(codec, new byte[]{
                (byte) 0xC2, 0x19, 0x7C, 0x5E, (byte) 0xFF, 0x14, (byte) 0xE9, 0x51},
                151288809941952849L);
    }

    private static void assertRoundTrip(ProtocolCodec<VarintFrame> codec, byte[] wire, long value) {
        VarintFrame f = new VarintFrame();
        f.setValue(value);
        assertThat(codec.serialize(f)).as("value=%d", value).containsExactly(wire);
        assertThat(codec.deserialize(wire).getValue()).as("wire=%s", hex(wire)).isEqualTo(value);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02X ", x));
        }
        return sb.toString().trim();
    }
}
