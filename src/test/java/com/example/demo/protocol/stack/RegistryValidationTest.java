package com.example.demo.protocol.stack;

import com.example.demo.protocol.HeartbeatMessage;
import com.example.demo.protocol.annotation.BindOn;
import com.example.demo.protocol.annotation.Protocol;
import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.core.PacketCodec;
import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 注册表校验与运行期匹配:重复 id、未知父、未知 when 标识符、优先级、宽松匹配。 */
class RegistryValidationTest {

    @Protocol(id = "dup-a")
    static class DupA {
        @ProtocolField(order = 1, size = 8) private int x;
    }

    @Protocol(id = "dup-a")
    static class DupB {
        @ProtocolField(order = 1, size = 8) private int x;
    }

    @Protocol(id = "orphan-child")
    @BindOn(parent = "no-such-parent", when = "x == 1")
    static class OrphanChild {
        @ProtocolField(order = 1, size = 8) private int x;
    }

    @Protocol(id = "bad-when")
    @BindOn(parent = "udp", when = "noSuchField == 1")
    static class BadWhen {
        @ProtocolField(order = 1, size = 8) private int x;
    }

    @Protocol(id = "bad-syntax")
    @BindOn(parent = "udp", when = "dstPort =! 1")
    static class BadSyntax {
        @ProtocolField(order = 1, size = 8) private int x;
    }

    @Test
    void duplicateIdFails() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ProtocolRegistry.create(DupA.class, DupB.class));
        assertTrue(e.getMessage().contains("duplicate protocol id 'dup-a'"));
    }

    @Test
    void unknownParentFails() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ProtocolRegistry.create(
                        com.example.demo.protocol.builtin.EthernetFrame.class,
                        com.example.demo.protocol.builtin.Ipv4Packet.class,
                        com.example.demo.protocol.builtin.UdpSegment.class,
                        OrphanChild.class));
        assertTrue(e.getMessage().contains("unknown parent 'no-such-parent'"));
    }

    @Test
    void unknownWhenIdentFails() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ProtocolRegistry.create(
                        com.example.demo.protocol.builtin.EthernetFrame.class,
                        com.example.demo.protocol.builtin.Ipv4Packet.class,
                        com.example.demo.protocol.builtin.UdpSegment.class,
                        BadWhen.class));
        assertTrue(e.getMessage().contains("unknown parent field 'noSuchField'"));
    }

    @Test
    void badWhenSyntaxFails() {
        assertThrows(IllegalArgumentException.class,
                () -> ProtocolRegistry.create(
                        com.example.demo.protocol.builtin.EthernetFrame.class,
                        com.example.demo.protocol.builtin.Ipv4Packet.class,
                        com.example.demo.protocol.builtin.UdpSegment.class,
                        BadSyntax.class));
    }

    @Test
    void matchChildEvaluatesWhen() {
        ProtocolRegistry r = TestStacks.registry();
        var udp = new com.example.demo.protocol.builtin.UdpSegment();
        udp.setSrcPort(1);
        udp.setDstPort(9999);
        assertEquals("my-app", r.matchChild("udp", udp));

        udp.setDstPort(1234);
        assertNull(r.matchChild("udp", udp));

        udp.setSrcPort(9998);   // srcPort 侧命中 heartbeat
        assertEquals("heartbeat", r.matchChild("udp", udp));
    }

    @Test
    void matchChildLenientOnUnsetFields() {
        ProtocolRegistry r = TestStacks.registry();
        var udp = new com.example.demo.protocol.builtin.UdpSegment();  // 端口字段为 0(默认值,视为已解析)
        // 0 不命中任何绑定 → null,不抛异常
        assertNull(r.matchChild("udp", udp));
    }

    @Test
    void entryMetadataExposed() {
        ProtocolRegistry r = TestStacks.registry();
        var entry = r.get("ipv4");
        assertNotNull(entry);
        assertTrue(entry.builtin());
        assertTrue(entry.codec() instanceof ProtocolCodec);
        assertTrue(r.byType(com.example.demo.protocol.MyProtocol.class).isPresent());
        assertEquals(8, r.all().size());
    }

    @Test
    void customPacketCodecPreferredOverReflective() {
        // L3 逃生舱:注册表使用手写 codec 而非反射式
        ProtocolRegistry r = ProtocolRegistry.create(
                com.example.demo.protocol.builtin.EthernetFrame.class,
                com.example.demo.protocol.builtin.Ipv4Packet.class,
                HandCodedProtocol.class);
        assertTrue(r.get("hand-coded").codec() instanceof HandCodec);

        @SuppressWarnings("rawtypes")
        PacketCodec codec = r.get("hand-coded").codec();
        HandCodedProtocol decoded = (HandCodedProtocol) codec.decode(new byte[]{0x5A}, 0, 1);
        assertEquals(0x5A, decoded.marker);
        assertArrayEquals(new byte[]{0x5A}, codec.encode(decoded));
        assertEquals(1, codec.headerBytes());
    }

    // ---- L3 逃生舱 fixture ----

    @Protocol(id = "hand-coded", codec = HandCodec.class)
    @BindOn(parent = "ipv4", when = "protocol == 250")
    public static class HandCodedProtocol {
        int marker;
    }

    public static class HandCodec implements PacketCodec<HandCodedProtocol> {
        @Override
        public HandCodedProtocol decode(byte[] data, int offset, int length) {
            HandCodedProtocol p = new HandCodedProtocol();
            p.marker = data[offset] & 0xFF;
            return p;
        }

        @Override
        public byte[] encode(HandCodedProtocol packet) {
            return new byte[]{(byte) packet.marker};
        }

        @Override
        public int headerBytes() {
            return 1;
        }
    }
}
