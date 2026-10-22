package com.netproto.protocols.real.ws;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.BitCursor;
import com.netproto.core.FieldCodec;
import com.netproto.core.FieldContext;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * WebSocket 帧真实向量测试(RFC 6455 §5.7)。
 * <p>
 * 规范示例向量:
 * <ul>
 *   <li>无掩码文本 "Hello":{@code 81 05 48 65 6C 6C 6F}</li>
 *   <li>掩码文本 "Hello"(mask key 37 FA 21 3D):{@code 81 85 37 FA 21 3D 7F 9F 4D 51 58}</li>
 * </ul>
 * 机制:7bit 长度 + 126/127 逃逸(presentIf 三态)、mask 位开关 4B key、
 * 掩码 payload(与 key mod-4 循环 XOR)由 L2 自定义 codec 从 ctx 取 key 处理。
 */
class WebSocketRealTest {

    /** 掩码载荷编解码:长度取自 len7/len16/len64,maskKey 取自 ctx,循环 XOR。 */
    public static class MaskedPayloadCodec implements FieldCodec<byte[]> {
        @Override
        public byte[] read(BitCursor cursor, FieldContext ctx, int remainingBytes) {
            byte[] data = cursor.readBytes(payloadLen(ctx) * 8);
            if (maskEnabled(ctx)) {
                unmask(data, maskKey(ctx));
            }
            return data;
        }

        @Override
        public void write(BitCursor cursor, FieldContext ctx, byte[] value) {
            byte[] out = value == null ? new byte[0] : value.clone();
            if (maskEnabled(ctx)) {
                unmask(out, maskKey(ctx));   // XOR 自逆
            }
            cursor.writeBytes(out);
        }

        @Override
        public long sizeOf(byte[] value) {
            return value == null ? 0 : value.length * 8L;
        }

        private static int payloadLen(FieldContext ctx) {
            int l7 = ctx.getInt("len7");
            if (l7 == 126) {
                return ctx.getInt("len16");
            }
            if (l7 == 127) {
                return (int) (long) (java.lang.Long) ctx.get("len64");
            }
            return l7;
        }

        private static boolean maskEnabled(FieldContext ctx) {
            return ctx.getInt("mask") == 1;
        }

        private static int maskKey(FieldContext ctx) {
            return ctx.getInt("maskKey");
        }

        /** RFC 6455 §5.3:payload[i] ^= key[i mod 4](key 按线上字节序,即 int 的 MSB-first 四字节)。 */
        private static void unmask(byte[] data, int key) {
            for (int i = 0; i < data.length; i++) {
                int k = (key >>> (24 - 8 * (i & 3))) & 0xFF;
                data[i] = (byte) ((data[i] & 0xFF) ^ k);
            }
        }
    }

    @Data
    @Protocol(id = "real-ws-frame")
    static class WsFrame {
        @ProtocolField(order = 1, size = 1)
        private int fin = 1;
        @ProtocolField(order = 2, size = 3)
        private int rsv;
        /** 1=text / 2=binary。 */
        @ProtocolField(order = 3, size = 4)
        private int opcode;
        @ProtocolField(order = 4, size = 1)
        private int mask;
        @ProtocolField(order = 5, size = 7)
        private int len7;
        @ProtocolField(order = 6, size = 16, presentIf = "len7==126")
        private int len16;
        @ProtocolField(order = 7, size = 64, type = FieldType.UNSIGNED, presentIf = "len7==127")
        private long len64;
        @ProtocolField(order = 8, size = 32, presentIf = "mask==1")
        private int maskKey;
        @ProtocolField(order = 9, type = FieldType.BYTES, custom = MaskedPayloadCodec.class)
        private byte[] payload = new byte[0];
    }

    // ---- 测试 ----

    /** RFC §5.7:无掩码 "Hello"。 */
    @Test
    void unmaskedHelloFromRfc() {
        ProtocolCodec<WsFrame> codec = new ProtocolCodec<>(WsFrame.class);
        WsFrame f = new WsFrame();
        f.setOpcode(1);
        f.setLen7(5);
        f.setPayload("Hello".getBytes());
        assertThat(codec.serialize(f)).containsExactly(
                (byte) 0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F);

        WsFrame back = codec.deserialize(new byte[]{
                (byte) 0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F});
        assertThat(new String(back.getPayload())).isEqualTo("Hello");
        assertThat(back.getOpcode()).isEqualTo(1);
    }

    /** RFC §5.7:掩码 "Hello",key=37 FA 21 3D,线上一致 + 解码还原。 */
    @Test
    void maskedHelloFromRfc() {
        ProtocolCodec<WsFrame> codec = new ProtocolCodec<>(WsFrame.class);
        WsFrame f = new WsFrame();
        f.setOpcode(1);
        f.setMask(1);
        f.setLen7(5);
        f.setMaskKey(0x37FA213D);
        f.setPayload("Hello".getBytes());
        assertThat(codec.serialize(f)).containsExactly(
                (byte) 0x81, (byte) 0x85,
                0x37, (byte) 0xFA, 0x21, 0x3D,
                0x7F, (byte) 0x9F, 0x4D, 0x51, 0x58);

        WsFrame back = codec.deserialize(new byte[]{
                (byte) 0x81, (byte) 0x85,
                0x37, (byte) 0xFA, 0x21, 0x3D,
                0x7F, (byte) 0x9F, 0x4D, 0x51, 0x58});
        assertThat(new String(back.getPayload())).isEqualTo("Hello");
        assertThat(back.getMaskKey()).isEqualTo(0x37FA213D);
    }

    /** 126 逃逸:300 字节文本走 16bit 长度分支。 */
    @Test
    void lengthEscapeTier126() {
        ProtocolCodec<WsFrame> codec = new ProtocolCodec<>(WsFrame.class);
        WsFrame f = new WsFrame();
        f.setOpcode(2);
        f.setLen7(126);
        f.setLen16(300);
        byte[] payload = new byte[300];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) i;
        }
        f.setPayload(payload);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(1 + 1 + 2 + 300);   // 头 + 0x7E 逃逸字节 + len16 + payload
        assertThat(wire[1]).isEqualTo((byte) 126);
        WsFrame back = codec.deserialize(wire);
        assertThat(back.getLen16()).isEqualTo(300);
        assertThat(back.getPayload()).containsExactly(payload);
    }
}
