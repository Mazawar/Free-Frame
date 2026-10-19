package com.example.demo.protocol.stack;

import com.example.demo.protocol.MyProtocol;
import com.example.demo.protocol.builtin.ArpPacket;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 自顶向下分派:全链下降、未注册协议停在已注册层、畸形层停止下降。 */
class StackDispatchTest {

    private final ProtocolRegistry registry = TestStacks.registry();
    private final StackDecoder decoder = new StackDecoder(registry, "ethernet");
    private final StackEncoder encoder = new StackEncoder(registry);

    @Test
    void fullStackDescendsToMyApp() {
        byte[] frame = encoder.encode(List.of(
                TestStacks.ethernet(), TestStacks.ipv4(), TestStacks.udp(44444, 9999),
                TestStacks.myApp(42, new byte[]{9, 8, 7})));

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 1);
        assertEquals(List.of("ethernet", "ipv4", "udp", "my-app"),
                decoded.layers().stream().map(DecodedPacket.DecodedLayer::id).toList());

        MyProtocol app = (MyProtocol) decoded.layers().get(3).packet();
        assertEquals(42, app.getSequenceId());
        assertEquals(2, app.getType());
        assertArrayEquals(new byte[]{9, 8, 7}, app.getPayloadData());
        assertEquals("my-app", decoded.deepestProtocol());
    }

    @Test
    void unregisteredPortStopsAtUdp() {
        byte[] frame = encoder.encode(List.of(
                TestStacks.ethernet(), TestStacks.ipv4(), TestStacks.udp(1234, 5678),
                TestStacks.myApp(1, new byte[]{1})));

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 2);
        // 5678 未注册任何业务协议 → 停在 udp,my-app 不会误命中
        assertEquals(List.of("ethernet", "ipv4", "udp"),
                decoded.layers().stream().map(DecodedPacket.DecodedLayer::id).toList());
    }

    @Test
    void arpBranch() {
        ArpPacket arp = new ArpPacket();
        arp.setOperation(1);
        arp.setSenderIp(TestStacks.ip("192.168.1.1"));
        arp.setTargetIp(TestStacks.ip("192.168.1.2"));
        byte[] frame = encoder.encode(List.of(TestStacks.ethernet(), arp));

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 3);
        assertEquals(List.of("ethernet", "arp"),
                decoded.layers().stream().map(DecodedPacket.DecodedLayer::id).toList());
        assertEquals(1, ((ArpPacket) decoded.layers().get(1).packet()).getOperation());
    }

    @Test
    void heartbeatWithCustomFieldCodecDescends() {
        byte[] frame = encoder.encode(List.of(
                TestStacks.ethernet(), TestStacks.ipv4(), TestStacks.udp(55555, 9998),
                TestStacks.heartbeat(300_000L, "gw1")));

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 4);
        assertEquals("heartbeat", decoded.deepestProtocol());
        assertEquals("ethernet▸ipv4▸udp▸heartbeat", decoded.protocolPath());
        com.example.demo.protocol.HeartbeatMessage hb =
                (com.example.demo.protocol.HeartbeatMessage) decoded.layers().get(3).packet();
        assertEquals(300_000L, hb.getUptimeMs());
        assertEquals("gw1", hb.getHostname());
    }

    @Test
    void malformedLayerStopsDescending() {
        // ethernet 合法,但 etherType=0x0800 之后只有 3 字节 —— ipv4 解析必失败
        byte[] frame = new byte[17];
        java.util.Arrays.fill(frame, (byte) 0);
        frame[12] = 0x08;
        frame[13] = 0x00;

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 5);
        assertEquals(List.of("ethernet"),
                decoded.layers().stream().map(DecodedPacket.DecodedLayer::id).toList());
    }

    @Test
    void truncatedEthernetYieldsEmptyLayers() {
        DecodedPacket decoded = decoder.decode(new byte[5], "test0", 0L, 6);
        assertTrue(decoded.layers().isEmpty());
        assertNull(decoded.deepestProtocol());
    }
}
