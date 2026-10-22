package com.netproto.protocols.real.coap;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.BitCursor;
import com.netproto.core.FieldCodec;
import com.netproto.core.FieldContext;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 真实协议测试 4:CoAP(RFC 7252)最小报文 —— CON GET,Token 0xAB,Uri-Path "t"→"s",payload "hi"。
 * <p>
 * 向量出处:RFC 7252 §3(首字节 Ver/Type/TKL)、§3.1(option nibble 半字节 delta/length)、
 * §4.6(payload 前置 0xFF 标记)。向量按任务给定:0x71 = delta7/len1(值 't'),
 * 0x01 = delta0/len1(值 's'),FF = payload 标记(编号=Σdelta 由编解码器内部累加,不在实体展开;
 * 语义 Uri-Path 时两个 option 编号同为 7 与 7+0,此处只验证半字节机不验证编号语义)。
 * <p>
 * 勘误(报告项,两处,向量本身不可解析故按 RFC 修正):
 * ① 任务书写 TKL 为 3bit,实为 RFC 7252 §3 的 4bit(Ver2+Type2+TKL4=8bit 恰一字节;
 *   若取 3bit,Code 会跨字节边界,编码结果整体错位 —— 已实测 41→42 02 24… 的 1bit 平移);
 * ② 任务向量首字节 0x40 的 TKL=0,则 Token 不存在,0xAB 会被当作 option 头
 *   (delta=10、len=11)且剩余字节不足 11,报文不可解析。TKL=1 → 首字节 = 01 00 0001 = 0x41。
 * <p>
 * 逃生舱说明:option 的半字节 delta/length(13→+1B 值+13、14→+2B 值+269、15 保留)
 * 与 payload 前置 0xFF 标记均超出声明式 DSL,按任务用 L2 自定义 FieldCodec 接管:
 * options 字段返回「原始 option 值字节 + 相对 delta」,编号(Σdelta)由编解码器内部累加,不展开。
 */
class CoapRealTest {

    /** 一个 CoAP option:相对上一个 option 的 delta + 原始值字节(编号 = Σdelta,不在实体展开)。 */
    record CoapOption(int delta, byte[] value) {
        CoapOption(int delta, String value) {
            this(delta, value.getBytes(StandardCharsets.US_ASCII));
        }
    }

    /** options 区(L2):读到 0xFF(payload 标记)或缓冲区尾停;不消费标记。 */
    public static class CoapOptionsCodec implements FieldCodec<List<CoapOption>> {

        @Override
        public List<CoapOption> read(BitCursor cursor, FieldContext ctx, int remainingBytes) {
            List<CoapOption> out = new ArrayList<>();
            while (cursor.peekByte() != -1 && cursor.peekByte() != 0xFF) {
                int header = (int) cursor.readBits(8) & 0xFF;
                int delta = readExt(cursor, header >>> 4);
                int length = readExt(cursor, header & 0x0F);
                out.add(new CoapOption(delta, cursor.readBytes(length * 8)));
            }
            return out;
        }

        @Override
        public void write(BitCursor cursor, FieldContext ctx, List<CoapOption> value) {
            for (CoapOption o : value == null ? List.<CoapOption>of() : value) {
                int deltaNibble = nibbleOf(o.delta(), "delta");
                int lengthNibble = nibbleOf(o.value().length, "length");
                cursor.writeBits((deltaNibble << 4) | lengthNibble, 8);
                writeExt(cursor, deltaNibble, o.delta());
                writeExt(cursor, lengthNibble, o.value().length);
                cursor.writeBytes(o.value());
            }
        }

        @Override
        public long sizeOf(List<CoapOption> value) {
            if (value == null) {
                return 0;
            }
            long bits = 0;
            for (CoapOption o : value) {
                bits += 8 + extBits(nibbleOf(o.delta(), "delta")) + extBits(nibbleOf(o.value().length, "length"))
                        + o.value().length * 8L;
            }
            return bits;
        }

        /** 半字节 0..12 直用;13 → +1B(值+13);14 → +2B(值+269);15 保留(仅整字节 0xFF 为标记)。 */
        private static int readExt(BitCursor c, int nibble) {
            if (nibble < 13) {
                return nibble;
            }
            if (nibble == 13) {
                return (int) c.readBits(8) + 13;
            }
            if (nibble == 14) {
                return (int) c.readBits(16) + 269;
            }
            throw new IllegalStateException("CoAP option nibble 15 is reserved");
        }

        private static int nibbleOf(int v, String what) {
            if (v <= 12) {
                return v;
            }
            if (v <= 268) {
                return 13;
            }
            if (v <= 65804) {
                return 14;
            }
            throw new IllegalArgumentException("CoAP option " + what + " too large: " + v);
        }

        private static void writeExt(BitCursor c, int nibble, int v) {
            if (nibble == 13) {
                c.writeBits(v - 13, 8);
            } else if (nibble == 14) {
                c.writeBits(v - 269, 16);
            }
        }

        private static int extBits(int nibble) {
            return nibble == 13 ? 8 : nibble == 14 ? 16 : 0;
        }
    }

    /** payload(L2):存在 payload 时前置 0xFF 标记字节;无 payload 则一字节不发。 */
    public static class CoapPayloadCodec implements FieldCodec<byte[]> {

        @Override
        public byte[] read(BitCursor cursor, FieldContext ctx, int remainingBytes) {
            if (remainingBytes > 0 && cursor.peekByte() == 0xFF) {
                cursor.skipBits(8);
                return cursor.readBytes((remainingBytes - 1) * 8);
            }
            return new byte[0];
        }

        @Override
        public void write(BitCursor cursor, FieldContext ctx, byte[] value) {
            if (value != null && value.length > 0) {
                cursor.writeBits(0xFF, 8);   // payload 标记
                cursor.writeBytes(value);
            }
        }

        @Override
        public long sizeOf(byte[] value) {
            return value == null || value.length == 0 ? 0 : 8L + value.length * 8L;
        }
    }

    /** CoAP 报文:头 32bit + Token(TKL 驱动)+ options(L2)+ payload(L2)。 */
    @Data
    @Protocol(id = "real-coap")
    static class CoapMessage {
        /** Ver = 1。 */
        @ProtocolField(order = 1, size = 2)
        private int ver = 1;
        /** Type = 0(CON)。 */
        @ProtocolField(order = 2, size = 2)
        private int type;
        /** Token Length(RFC 7252 §3:4bit,0..8)。 */
        @ProtocolField(order = 3, size = 4)
        private int tkl;
        /** Code = 0.01(GET)= 0x01。 */
        @ProtocolField(order = 4, size = 8)
        private int code;
        @ProtocolField(order = 5, size = 16)
        private int msgId;
        @ProtocolField(order = 6, lengthField = "tkl", type = FieldType.BYTES)
        private byte[] token = new byte[0];
        @ProtocolField(order = 7, custom = CoapOptionsCodec.class)
        private List<CoapOption> options = new ArrayList<>();
        @ProtocolField(order = 8, custom = CoapPayloadCodec.class)
        private byte[] payload = new byte[0];
    }

    // ---- 测试 ----

    /**
     * 主向量:41 01 12 34 AB 71 74 01 73 FF 68 69(12 字节;首字节 0x41 见类注释勘误)。
     * 断言:头部字节 + options/payload 字节 + round-trip。
     */
    @Test
    void conGetWithTwoUriPathsMatchesVectorAndRoundTrips() {
        ProtocolCodec<CoapMessage> codec = new ProtocolCodec<>(CoapMessage.class);
        CoapMessage m = new CoapMessage();   // ver=1 type=0(CON)
        m.setTkl(1);
        m.setCode(0x01);   // 0.01 GET
        m.setMsgId(0x1234);
        m.setToken(new byte[]{(byte) 0xAB});
        m.setOptions(List.of(new CoapOption(7, "t"), new CoapOption(0, "s")));
        m.setPayload("hi".getBytes(StandardCharsets.US_ASCII));

        byte[] wire = codec.serialize(m);
        assertThat(wire).containsExactly(0x41, 0x01, 0x12, 0x34,   // 头:Ver1/Type0/TKL1 + code + msgId
                0xAB,                                                // token(TKL 驱动)
                0x71, 0x74,                                          // option1:delta7/len1 + 't'
                0x01, 0x73,                                          // option2:delta0/len1 + 's'
                0xFF,                                                // payload 标记
                0x68, 0x69);                                         // "hi"
        // 分段字节级断言
        assertThat(wire[0]).isEqualTo((byte) 0x41);
        assertThat(wire[4]).isEqualTo((byte) 0xAB);
        assertThat(wire[5]).isEqualTo((byte) 0x71);
        assertThat(wire[6]).isEqualTo((byte) 0x74);
        assertThat(wire[7]).isEqualTo((byte) 0x01);
        assertThat(wire[8]).isEqualTo((byte) 0x73);
        assertThat(wire[9]).isEqualTo((byte) 0xFF);
        assertThat(Arrays.copyOfRange(wire, 10, 12)).containsExactly(0x68, 0x69);

        CoapMessage back = codec.deserialize(wire);
        assertThat(back.getVer()).isEqualTo(1);
        assertThat(back.getType()).isEqualTo(0);
        assertThat(back.getTkl()).isEqualTo(1);
        assertThat(back.getCode()).isEqualTo(0x01);
        assertThat(back.getMsgId()).isEqualTo(0x1234);
        assertThat(back.getToken()).containsExactly(0xAB);
        assertThat(back.getOptions()).hasSize(2);
        assertThat(back.getOptions().get(0).delta()).isEqualTo(7);
        assertThat(back.getOptions().get(0).value()).containsExactly(0x74);   // 't'
        assertThat(back.getOptions().get(1).delta()).isEqualTo(0);
        assertThat(back.getOptions().get(1).value()).containsExactly(0x73);   // 's'
        assertThat(back.getPayload()).containsExactly(0x68, 0x69);            // "hi"
        assertThat(codec.serialize(back)).containsExactly(wire);
    }

    /** 半字节 13 逃逸:option 值长 13(>12)→ len 半字节 13 + 1B 扩展(值-13=0);delta 13 同理。 */
    @Test
    void optionLengthAndDeltaEscape13UseOneExtendedByte() {
        ProtocolCodec<CoapMessage> codec = new ProtocolCodec<>(CoapMessage.class);
        CoapMessage m = new CoapMessage();   // TKL=0,无 token
        m.setCode(0x01);
        m.setMsgId(0x0001);
        byte[] thirteen = new byte[13];
        Arrays.fill(thirteen, (byte) 'a');
        m.setOptions(List.of(new CoapOption(13, thirteen)));   // delta=13 与 length=13 都走 13 逃逸

        byte[] wire = codec.serialize(m);
        assertThat(wire).hasSize(4 + 3 + 13);
        assertThat(wire[0]).isEqualTo((byte) 0x40);   // Ver1/Type0/TKL0(此处 TKL=0,首字节恰为 0x40)
        assertThat(wire[4]).isEqualTo((byte) 0xDD);   // delta 半字节 13 | length 半字节 13
        assertThat(wire[5]).isEqualTo((byte) 0x00);   // delta 扩展:13 - 13 = 0
        assertThat(wire[6]).isEqualTo((byte) 0x00);   // length 扩展:13 - 13 = 0
        assertThat(wire[7]).isEqualTo((byte) 0x61);

        CoapMessage back = codec.deserialize(wire);
        assertThat(back.getOptions()).hasSize(1);
        assertThat(back.getOptions().get(0).delta()).isEqualTo(13);
        assertThat(back.getOptions().get(0).value()).hasSize(13);
    }

    /** 半字节 14 逃逸:option 值长 300(≥269)→ len 半字节 14 + 2B 扩展(300-269=31=0x001F)。 */
    @Test
    void optionLengthEscape14UsesTwoExtendedBytes() {
        ProtocolCodec<CoapMessage> codec = new ProtocolCodec<>(CoapMessage.class);
        CoapMessage m = new CoapMessage();
        m.setCode(0x01);
        byte[] big = new byte[300];
        Arrays.fill(big, (byte) 'z');
        m.setOptions(List.of(new CoapOption(0, big)));

        byte[] wire = codec.serialize(m);
        assertThat(wire).hasSize(4 + 3 + 300);
        assertThat(wire[4]).isEqualTo((byte) 0x0E);   // delta 半字节 0 | length 半字节 14
        assertThat(wire[5]).isEqualTo((byte) 0x00);   // length 扩展 BE 高字节
        assertThat(wire[6]).isEqualTo((byte) 0x1F);   // length 扩展 BE 低字节(300-269)

        CoapMessage back = codec.deserialize(wire);
        assertThat(back.getOptions().get(0).value()).hasSize(300);
    }

    /** 半字节 15 保留:delta 半字节 15 且非 0xFF 标记 → 干净拒绝。 */
    @Test
    void reservedNibble15IsRejected() {
        ProtocolCodec<CoapMessage> codec = new ProtocolCodec<>(CoapMessage.class);
        byte[] bad = hex("41 01 12 34 AB F0");   // 0xF0:delta 半字节 15、length 0 ≠ 15,非法
        RuntimeException ex = assertThrows(RuntimeException.class, () -> codec.deserialize(bad));
        assertThat(ex.getCause()).hasMessageContaining("reserved");
    }

    // ---- 小工具 ----

    private static byte[] hex(String s) {
        String clean = s.replaceAll("\\s+", "");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
