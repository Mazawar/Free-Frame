package com.netproto.stack;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.PacketCodec;
import com.netproto.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** 注册表校验与运行期匹配:重复 id、未知父、未知 when 标识符、优先级前手写 codec(L3)。 */
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
    @BindOn(parent = "mini-udp", when = "noSuchField == 1")
    static class BadWhen {
        @ProtocolField(order = 1, size = 8) private int x;
    }

    @Protocol(id = "bad-syntax")
    @BindOn(parent = "mini-udp", when = "dstPort =! 1")
    static class BadSyntax {
        @ProtocolField(order = 1, size = 8) private int x;
    }

    private static ProtocolRegistry fullRegistry(Class<?>... extra) {
        java.util.List<Class<?>> all = new java.util.ArrayList<>(java.util.Arrays.asList(
                TestStacks.MiniEth.class, TestStacks.MiniIp.class, TestStacks.MiniUdp.class));
        all.addAll(java.util.Arrays.asList(extra));
        return ProtocolRegistry.create(all);
    }

        @Test
    void adjacentAlignedGroupRegisters() {
        ProtocolRegistry r = fullRegistry(GroupOk.class);
        assertNotNull(r.get("group-ok"));
    }

    @Test
    void groupMembersMustBeAdjacent() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> fullRegistry(GroupGap.class));
        assertTrue(e.getMessage().contains("must be adjacent"));
    }

    @Test
    void groupTotalWidthMustBeByteAligned() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> fullRegistry(GroupUnaligned.class));
        assertTrue(e.getMessage().contains("not byte-aligned"));
    }

    @Test
    void groupMembersMustHaveFixedSize() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> fullRegistry(GroupVariable.class));
        assertTrue(e.getMessage().contains("fixed size"));
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
                () -> fullRegistry(OrphanChild.class));
        assertTrue(e.getMessage().contains("unknown parent 'no-such-parent'"));
    }

    @Test
    void unknownWhenIdentFails() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> fullRegistry(BadWhen.class));
        assertTrue(e.getMessage().contains("unknown parent field 'noSuchField'"));
    }

    @Test
    void badWhenSyntaxFails() {
        assertThrows(IllegalArgumentException.class, () -> fullRegistry(BadSyntax.class));
    }

    @Test
    void matchChildEvaluatesWhen() {
        ProtocolRegistry r = TestStacks.registry();
        TestStacks.MiniUdp udp = new TestStacks.MiniUdp();
        udp.setSrcPort(1);
        udp.setDstPort(9999);
        assertEquals("mini-app", r.matchChild("mini-udp", udp));

        udp.setDstPort(1234);
        assertNull(r.matchChild("mini-udp", udp));

        udp.setSrcPort(9998);   // srcPort 侧命中 mini-hb
        assertEquals("mini-hb", r.matchChild("mini-udp", udp));

        udp.setSrcPort(0);      // 无任何命中
        assertNull(r.matchChild("mini-udp", udp));
    }

    @Test
    void entryMetadataExposed() {
        ProtocolRegistry r = TestStacks.registry();
        ProtocolRegistry.Entry entry = r.get("mini-ip");
        assertNotNull(entry);
        assertFalse(entry.builtin());
        assertTrue(entry.codec() instanceof ProtocolCodec);
        assertTrue(r.byType(TestStacks.MiniApp.class).isPresent());
        assertEquals(6, r.all().size());
    }

    @Test
    void customPacketCodecPreferredOverReflective() {
        // L3 逃生舱:注册表使用手写 codec 而非反射式
        ProtocolRegistry r = ProtocolRegistry.create(
                TestStacks.MiniEth.class, TestStacks.MiniIp.class, HandCodedProtocol.class);
        assertTrue(r.get("hand-coded").codec() instanceof HandCodec);

        @SuppressWarnings("rawtypes")
        PacketCodec codec = r.get("hand-coded").codec();
        HandCodedProtocol decoded = (HandCodedProtocol) codec.decode(new byte[]{0x5A}, 0, 1);
        assertEquals(0x5A, decoded.marker);
        assertArrayEquals(new byte[]{0x5A}, codec.encode(decoded));
        assertEquals(1, codec.headerBytes());
    }


    // ---- 展示分组(@ProtocolField#group)fixture ----

    @Protocol(id = "group-ok")
    static class GroupOk {
        @ProtocolField(order = 1, size = 8) private int a;
        @ProtocolField(order = 2, size = 4, group = "Flags") private int f1;
        @ProtocolField(order = 3, size = 4, group = "Flags") private int f2;
    }

    @Protocol(id = "group-gap")
    static class GroupGap {
        @ProtocolField(order = 1, size = 4, group = "G") private int a;
        @ProtocolField(order = 2, size = 8) private int mid;
        @ProtocolField(order = 3, size = 4, group = "G") private int b;
    }

    @Protocol(id = "group-unaligned")
    static class GroupUnaligned {
        @ProtocolField(order = 1, size = 3, group = "G") private int a;
        @ProtocolField(order = 2, size = 3, group = "G") private int b;
    }

    @Protocol(id = "group-variable")
    static class GroupVariable {
        // 组内变长成员:BYTES+lengthField(codec 层合法的动态长度),组校验应拒绝
        @ProtocolField(order = 1, size = 8, group = "G") private int len;
        @ProtocolField(order = 2, lengthField = "len", group = "G") private byte[] b;
    }

    // ---- L3 逃生舱 fixture ----

    @Protocol(id = "hand-coded", codec = HandCodec.class)
    @BindOn(parent = "mini-ip", when = "proto == 250")
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
