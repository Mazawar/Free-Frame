package com.example.netproto.stack;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 自顶向下分派:全链下降、未注册协议停在已注册层、畸形层停止下降。 */
class StackDispatchTest {

    private final ProtocolRegistry registry = TestStacks.registry();
    private final StackDecoder decoder = new StackDecoder(registry, "mini-eth");
    private final StackEncoder encoder = new StackEncoder(registry);

    @Test
    void fullStackDescendsToApp() {
        byte[] frame = encoder.encode(List.of(
                TestStacks.MiniEth.frame(),
                TestStacks.MiniIp.packet(TestStacks.SRC_IP, TestStacks.DST_IP),
                TestStacks.MiniUdp.segment(44444, 9999),
                TestStacks.MiniApp.message(42, new byte[]{9, 8, 7})));

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 1);
        assertEquals(List.of("mini-eth", "mini-ip", "mini-udp", "mini-app"),
                decoded.layers().stream().map(DecodedPacket.DecodedLayer::id).toList());

        TestStacks.MiniApp app = (TestStacks.MiniApp) decoded.layers().get(3).packet();
        assertEquals(42, app.getSequenceId());
        assertEquals(2, app.getType());
        assertArrayEquals(new byte[]{9, 8, 7}, app.getPayloadData());
        assertEquals("mini-app", decoded.deepestProtocol());

        // 字段字节区间(联动高亮数据源):eth 头 dstMac [0,6);udp payload 覆盖内层 app
        var ethRanges = decoded.layers().get(0).fieldRanges();
        assertArrayEquals(new int[]{0, 6}, ethRanges.get("dstMac"));
        var udpRanges = decoded.layers().get(2).fieldRanges();
        assertArrayEquals(new int[]{34, 43}, udpRanges.get("payload"));   // 34=14+14+6,43=帧尾(app 头6+payload3)
        var appRanges = decoded.layers().get(3).fieldRanges();
        assertArrayEquals(new int[]{40, 43}, appRanges.get("payloadData"));
    }

    @Test
    void unregisteredPortStopsAtTransportLayer() {
        byte[] frame = encoder.encode(List.of(
                TestStacks.MiniEth.frame(),
                TestStacks.MiniIp.packet(TestStacks.SRC_IP, TestStacks.DST_IP),
                TestStacks.MiniUdp.segment(1234, 5678),
                TestStacks.MiniApp.message(1, new byte[]{1})));

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 2);
        // 5678 未注册任何业务协议 → 停在 mini-udp(autoWire 只填未设置字段,不覆盖显式端口)
        assertEquals(List.of("mini-eth", "mini-ip", "mini-udp"),
                decoded.layers().stream().map(DecodedPacket.DecodedLayer::id).toList());
    }

    @Test
    void leafProtocolDirectlyUnderRoot() {
        TestStacks.MiniLeaf leaf = new TestStacks.MiniLeaf();
        leaf.setOp(1);
        leaf.setTarget(0xAAAAAAAAAAAAL);
        byte[] frame = encoder.encode(List.of(TestStacks.MiniEth.frame(), leaf));

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 3);
        assertEquals(List.of("mini-eth", "mini-leaf"),
                decoded.layers().stream().map(DecodedPacket.DecodedLayer::id).toList());
        assertEquals(1, ((TestStacks.MiniLeaf) decoded.layers().get(1).packet()).getOp());
    }

    @Test
    void customFieldCodecDescendsThroughDispatch() {
        byte[] frame = encoder.encode(List.of(
                TestStacks.MiniEth.frame(),
                TestStacks.MiniIp.packet(TestStacks.SRC_IP, TestStacks.DST_IP),
                TestStacks.MiniUdp.segment(55555, 9998),
                TestStacks.MiniHb.of(300_000L, "gw1")));

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 4);
        assertEquals("mini-hb", decoded.deepestProtocol());
        assertEquals("mini-eth▸mini-ip▸mini-udp▸mini-hb", decoded.protocolPath());
        TestStacks.MiniHb hb = (TestStacks.MiniHb) decoded.layers().get(3).packet();
        assertEquals(300_000L, hb.getUptimeMs());
        assertEquals("gw1", hb.getHostname());
    }

    @Test
    void malformedLayerStopsDescending() {
        // mini-eth 合法,但 etherType=0x0800 之后只有 3 字节 —— mini-ip 解析必失败
        byte[] frame = new byte[17];
        java.util.Arrays.fill(frame, (byte) 0);
        frame[12] = 0x08;
        frame[13] = 0x00;

        DecodedPacket decoded = decoder.decode(frame, "test0", 0L, 5);
        assertEquals(List.of("mini-eth"),
                decoded.layers().stream().map(DecodedPacket.DecodedLayer::id).toList());
    }

    @Test
    void truncatedRootYieldsEmptyLayers() {
        DecodedPacket decoded = decoder.decode(new byte[5], "test0", 0L, 6);
        assertTrue(decoded.layers().isEmpty());
        assertNull(decoded.deepestProtocol());
    }
}
