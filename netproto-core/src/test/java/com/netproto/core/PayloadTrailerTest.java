package com.netproto.core;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.ChecksumField;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.stack.DecodedPacket;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackDecoder;
import com.netproto.stack.StackEncoder;
import lombok.Data;
import lombok.ToString;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 「@Payload 长度驱动 + 尾随字段」引擎特性验证 —— 公共头 + 类型分派 + 帧尾校验形态的原生表达。
 * <pre>
 * | signalType(1B) | frameLength(2B) | body(N = frameLength-5) | crc(2B) |
 *   头 3B + body + 尾 2B;crc = 头+体求和(编码期置0→序列化→回填,覆盖含 body 的全帧)。
 * </pre>
 * 关键语义:body 用 @Payload + @ProtocolField(lengthField) 声明后
 * ① 解码按长度截断,其后尾随字段照常读;② 子协议分派入口停在 body 起点(不被尾随字段吃掉);
 * ③ 编码一致性:lengthField 推导字节数必须等于实际 payload(onPayload/手工设置)。
 */
class PayloadTrailerTest {

    @Data
    @ToString
    @Protocol(id = "tl-frame", name = "尾随CRC帧")
    static class TrailerFrame implements Checksum, PayloadAware {

        @ProtocolField(order = 1, size = 8)
        private int signalType = 1;

        /** 整帧长度 = 3 头 + body + 2 CRC(组装期 onPayload 自动回填)。 */
        @ProtocolField(order = 2, size = 16)
        private int frameLength;

        /** 长度驱动 @Payload:body = frameLength - 5(3 头 + 2 CRC)。 */
        @Payload
        @ProtocolField(order = 3, lengthField = "frameLength", lengthAdjust = -5)
        private byte[] body = new byte[0];

        /** 尾随校验:覆盖头+体(计算时自身已置 0,排除最后 2B)。 */
        @ProtocolField(order = 4, size = 16)
        @ChecksumField
        private int crc;

        @Override
        public void onPayload(byte[] inner) {
            this.frameLength = 5 + inner.length;
        }

        @Override
        public long compute(String field, byte[] serialized) {
            if (!"crc".equals(field)) {
                return -1;
            }
            int sum = 0;
            for (int i = 0; i < serialized.length - 2; i++) {
                sum += serialized[i] & 0xFF;
            }
            return sum & 0xFFFF;
        }
    }

    @Data
    @ToString
    @Protocol(id = "tl-child", name = "尾随帧信令A")
    @BindOn(parent = "tl-frame", when = "signalType == 1")
    static class TlChildA {
        @ProtocolField(order = 1, size = 8)
        private int code;
        @ProtocolField(order = 2, size = 16)
        private int value;
    }

    /** 反例夹具:@Payload 带 @ProtocolField 却缺 lengthField → 注册期拒绝。 */
    static class BrokenFrame {
        @Payload
        @ProtocolField(order = 1)
        private byte[] body = new byte[0];
    }

    private static ProtocolRegistry registry;
    private static StackEncoder encoder;
    private static StackDecoder decoder;

    @BeforeAll
    static void init() {
        registry = ProtocolRegistry.create(TrailerFrame.class, TlChildA.class);
        registry.validateBindings();
        encoder = new StackEncoder(registry);
        decoder = new StackDecoder(registry, "tl-frame");
    }

    @Test
    @DisplayName("整栈编码:长度/选择子/CRC 全自动 —— [01][0008][body 3B][crc 2B] 逐字节核对")
    void fullStackEncodeAutoWiresEverything() {
        TrailerFrame frame = new TrailerFrame();
        TlChildA child = new TlChildA();
        child.setCode(0x0A);
        child.setValue(0x1234);

        // wrap:body 注入 → onPayload 回填 frameLength=8 → autoWire 接线 signalType=1 → 编码 → CRC 回填
        byte[] wire = encoder.encode(List.of(frame, child));

        int expectedCrc = ((0x01 + 0x00 + 0x08 + 0x0A + 0x12 + 0x34) & 0xFFFF);
        assertEquals("01 00 08 0A 12 34", hex(java.util.Arrays.copyOf(wire, 6)));
        assertEquals(expectedCrc, ((wire[6] & 0xFF) << 8) | (wire[7] & 0xFF));
        assertEquals(8, wire.length);
    }

    @Test
    @DisplayName("解码:尾随 CRC 照常读出,子协议从 body 起分派到底(核心语义)")
    void decodeKeepsDispatchAndReadsTrailer() {
        int crc = 0x01 + 0x00 + 0x08 + 0x0A + 0x12 + 0x34;
        byte[] wire = hex(String.format("01 00 08 0A 12 34 %02X %02X",
                (crc >> 8) & 0xFF, crc & 0xFF));

        DecodedPacket p = decoder.decode(wire, "test", 0, 1);

        // 分派入口 = body 起点(头 3B 后),不被尾随 CRC 吃掉
        assertEquals("tl-frame▸tl-child", p.protocolPath());
        TrailerFrame back = (TrailerFrame) p.layers().get(0).packet();
        assertEquals(8, back.getFrameLength());
        assertArrayEquals(hex("0A 12 34"), back.getBody());
        assertEquals(crc, back.getCrc());
        TlChildA c = (TlChildA) p.layers().get(1).packet();
        assertEquals(0x0A, c.getCode());
        assertEquals(0x1234, c.getValue());
    }

    @Test
    @DisplayName("单层 round-trip:孤立帧(无子协议)同样工作,CRC 自动回填")
    void islandRoundTrip() {
        TrailerFrame frame = new TrailerFrame();
        frame.setBody(hex("DE AD BE EF"));
        frame.setFrameLength(5 + 4);                       // 单层编码无 wrap → 手工置长度

        byte[] wire = new ProtocolCodec<>(TrailerFrame.class).encode(frame);
        assertEquals(9, wire.length);

        DecodedPacket p = decoder.decode(wire, "test", 0, 1);
        TrailerFrame back = (TrailerFrame) p.layers().get(0).packet();
        assertArrayEquals(hex("DE AD BE EF"), back.getBody());
        int sum = 0;                                       // 独立复算:头+体求和(引擎只回填字节,不改 POJO)
        for (int i = 0; i < 7; i++) sum += wire[i] & 0xFF;
        assertEquals(sum & 0xFFFF, back.getCrc());
    }

    @Test
    @DisplayName("编码一致性:lengthField 与实际 payload 不符 → 明确报错而非静默错帧")
    void encodeRejectsInconsistentLength() {
        TrailerFrame frame = new TrailerFrame();
        frame.setBody(hex("01 02 03"));
        frame.setFrameLength(99);                          // 与 body 不一致

        RuntimeException e = assertThrows(RuntimeException.class,
                () -> new ProtocolCodec<>(TrailerFrame.class).encode(frame));
        assertTrue(e.getMessage().contains("implies"),
                "error should explain the mismatch: " + e.getMessage());
    }

    @Test
    @DisplayName("注册期拒绝:@Payload + @ProtocolField 缺 lengthField(两种模式二选一)")
    void registrationRejectsPayloadWithoutLengthField() {
        assertThrows(IllegalArgumentException.class,
                () -> ProtocolRegistry.create(BrokenFrame.class));
    }

    // ---- 辅助 ----

    private static byte[] hex(String s) {
        String clean = s.replace(" ", "");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", b[i]));
        }
        return sb.toString();
    }
}
