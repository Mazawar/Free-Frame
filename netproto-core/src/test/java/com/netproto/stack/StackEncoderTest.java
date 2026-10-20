package com.netproto.stack;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 自底向上组装:选择子自动接线、长度钩子、校验和、线格式正确性。
 * 迷你栈布局:eth14 | ip14 | udp6 | app(6+payload)。
 */
class StackEncoderTest {

    private final ProtocolRegistry registry = TestStacks.registry();
    private final StackEncoder encoder = new StackEncoder(registry);

    private List<?> appFrame() {
        return List.of(
                TestStacks.MiniEth.frame(),
                TestStacks.MiniIp.packet(TestStacks.SRC_IP, TestStacks.DST_IP),
                TestStacks.MiniUdp.segment(44444, 9999),
                TestStacks.MiniApp.message(7, new byte[]{1, 2}));
    }

    @Test
    void selectorsAndLengthsAreAutoWired() {
        byte[] frame = encoder.encode(appFrame());

        // app = 6 头 + 2 payload = 8B;frame = 14+14+6+8 = 42
        assertEquals(42, frame.length);

        assertEquals(0x08, frame[12] & 0xFF);   // etherType = 0x0800(自动接线)
        assertEquals(0x00, frame[13] & 0xFF);
        int ipTotal = ((frame[15] & 0xFF) << 8) | (frame[16] & 0xFF);
        assertEquals(28, ipTotal);               // mini-ip.totalLength = 14 + 14(钩子)
        assertEquals(17, frame[17] & 0xFF);      // proto = 17(自动接线)
        int dstPort = ((frame[30] & 0xFF) << 8) | (frame[31] & 0xFF);
        assertEquals(9999, dstPort);             // 端口来自 when 第一子句(自动接线)
        int udpLen = ((frame[32] & 0xFF) << 8) | (frame[33] & 0xFF);
        assertEquals(14, udpLen);                // mini-udp.length = 6 + 8(钩子)
    }

    @Test
    void explicitSelectorsAreNotOverwritten() {
        // 用户显式把端口设为 5678:autoWire 不得覆盖(用于改道/未注册端口场景)
        byte[] frame = encoder.encode(List.of(
                TestStacks.MiniEth.frame(),
                TestStacks.MiniIp.packet(TestStacks.SRC_IP, TestStacks.DST_IP),
                TestStacks.MiniUdp.segment(1234, 5678),
                TestStacks.MiniApp.message(1, new byte[]{1})));
        int dstPort = ((frame[30] & 0xFF) << 8) | (frame[31] & 0xFF);
        assertEquals(5678, dstPort);
    }

    @Test
    void ipHeaderChecksumIsValid() {
        byte[] frame = encoder.encode(appFrame());
        // mini-ip 头 14 字节(frame[14..27])反码求和(含校验和)应为 0xFFFF
        long sum = 0;
        for (int i = 14; i + 1 < 28; i += 2) {
            sum += ((frame[i] & 0xFF) << 8) | (frame[i + 1] & 0xFF);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assertEquals(0xFFFF, sum & 0xFFFF);
    }

    @Test
    void roundTripThroughDecoderKeepsAppFields() {
        byte[] frame = encoder.encode(appFrame());
        DecodedPacket decoded = new StackDecoder(registry, "mini-eth").decode(frame, "t", 0L, 1);

        TestStacks.MiniIp ip = (TestStacks.MiniIp) decoded.layers().get(1).packet();
        assertEquals(TestStacks.SRC_IP, ip.getSourceIp());
        TestStacks.MiniUdp udp = (TestStacks.MiniUdp) decoded.layers().get(2).packet();
        assertEquals(9999, udp.getDstPort());
        TestStacks.MiniApp app = (TestStacks.MiniApp) decoded.layers().get(3).packet();
        assertEquals(7, app.getSequenceId());
        assertArrayEquals(new byte[]{1, 2}, app.getPayloadData());
    }

    @Test
    void singleLayerEncodeAndUnknownTypeRejected() {
        byte[] single = encoder.encode(List.of(TestStacks.MiniApp.message(1, new byte[0])));
        assertEquals(6, single.length);

        assertThrows(IllegalArgumentException.class,
                () -> encoder.encode(List.of(new Object())));  // 未注册类型
        assertThrows(IllegalArgumentException.class,
                () -> encoder.encode(List.of()));
    }
}
