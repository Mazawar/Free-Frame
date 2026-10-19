package com.example.demo.protocol.stack;

import com.example.demo.protocol.builtin.Ipv4Packet;
import com.example.demo.protocol.builtin.UdpSegment;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 自底向上组装:选择子自动接线、长度钩子、校验和、线格式正确性。 */
class StackEncoderTest {

    private final ProtocolRegistry registry = TestStacks.registry();
    private final StackEncoder encoder = new StackEncoder(registry);

    @Test
    void selectorsAndLengthsAreAutoWired() {
        byte[] frame = encoder.encode(List.of(
                TestStacks.ethernet(), TestStacks.ipv4(), TestStacks.udp(44444, 9999),
                TestStacks.myApp(7, new byte[]{1, 2})));

        // my-app = 1+1+2+4 头 + 2 payload = 10B
        // 以太网 14 + IP 20 + UDP 8 + 10 = 52
        assertEquals(52, frame.length);

        assertEquals(0x08, (frame[12] & 0xFF));      // etherType = 0x0800(自动接线)
        assertEquals(0x00, (frame[13] & 0xFF));
        int udpStart = 34;
        int udpLenWord = ((frame[udpStart + 4] & 0xFF) << 8) | (frame[udpStart + 5] & 0xFF);
        assertEquals(18, udpLenWord);                 // udp.length = 8 + 10(钩子)
        int ipTotalWord = ((frame[16] & 0xFF) << 8) | (frame[17] & 0xFF);  // IP 头内偏移 2-3
        assertEquals(38, ipTotalWord);                // ip.totalLength = 20 + 18(钩子)
        int dstPortWord = ((frame[udpStart + 2] & 0xFF) << 8) | (frame[udpStart + 3] & 0xFF);
        assertEquals(9999, dstPortWord);              // 端口来自 when 第一子句(自动接线)
        int protoByte = frame[23] & 0xFF;
        assertEquals(17, protoByte);                  // ip.protocol = 17(自动接线)
    }

    @Test
    void ipv4HeaderChecksumIsValid() {
        byte[] frame = encoder.encode(List.of(
                TestStacks.ethernet(), TestStacks.ipv4(), TestStacks.udp(1, 9999),
                TestStacks.myApp(1, new byte[]{5})));

        // 头 20 字节反码求和应为 0(含校验和自身)
        long sum = 0;
        for (int i = 14; i + 1 < 34; i += 2) {
            sum += ((frame[i] & 0xFF) << 8) | (frame[i + 1] & 0xFF);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assertEquals(0xFFFF, sum & 0xFFFF);
    }

    @Test
    void roundTripThroughDecoderKeepsAppFields() {
        byte[] frame = encoder.encode(List.of(
                TestStacks.ethernet(), TestStacks.ipv4(), TestStacks.udp(44444, 9999),
                TestStacks.myApp(99, new byte[]{7, 7, 7})));
        DecodedPacket decoded = new StackDecoder(registry, "ethernet").decode(frame, "t", 0L, 1);

        Ipv4Packet ip = (Ipv4Packet) decoded.layers().get(1).packet();
        assertEquals(TestStacks.SRC_IP, ip.getSourceIp());
        UdpSegment udp = (UdpSegment) decoded.layers().get(2).packet();
        assertEquals(9999, udp.getDstPort());
        var app = (com.example.demo.protocol.MyProtocol) decoded.layers().get(3).packet();
        assertEquals(99, app.getSequenceId());
        assertArrayEquals(new byte[]{7, 7, 7}, app.getPayloadData());
    }

    @Test
    void singleLayerEncodeAndUnknownTypeRejected() {
        byte[] arpless = encoder.encode(List.of(TestStacks.myApp(1, new byte[0])));
        assertEquals(8, arpless.length);

        assertThrows(IllegalArgumentException.class,
                () -> encoder.encode(List.of(new Object())));  // 未注册类型
        assertThrows(IllegalArgumentException.class,
                () -> encoder.encode(List.of()));
    }
}
