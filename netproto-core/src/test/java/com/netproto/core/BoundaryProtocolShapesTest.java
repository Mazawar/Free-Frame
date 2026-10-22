package com.netproto.core;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 能力边界测试:调研矩阵直接映射的「真实协议形态」。
 * <ul>
 *   <li>ARP:hlen/plen 双前序字段驱动四个变长地址字段(M13 教科书形态);</li>
 *   <li>WebSocket:7bit 长度 + 126/127 逃逸到 16/64bit(M10 长度逃逸);</li>
 *   <li>SCTP/DCP:长度不含尾部、pad 到 4 字节对齐(M30);</li>
 *   <li>HART:分隔符 bit2 切换短地址(1B)/长地址(5B)双形态(M25);</li>
 *   <li>XModem:首字节 SOH/STX 值直接选择 128B/1024B 块(值域即长度)。</li>
 * </ul>
 */
class BoundaryProtocolShapesTest {

    // ---- ARP 式 ----

    @Data
    @Protocol(id = "b-arp")
    static class ArpLikeFrame {
        @ProtocolField(order = 1, size = 16)
        private int htype;
        @ProtocolField(order = 2, size = 16)
        private int ptype;
        @ProtocolField(order = 3, size = 8)
        private int hlen = 6;
        @ProtocolField(order = 4, size = 8)
        private int plen = 4;
        @ProtocolField(order = 5, size = 16)
        private int oper;
        @ProtocolField(order = 6, lengthField = "hlen", type = FieldType.BYTES)
        private byte[] sha;
        @ProtocolField(order = 7, lengthField = "plen", type = FieldType.BYTES)
        private byte[] spa;
        @ProtocolField(order = 8, lengthField = "hlen", type = FieldType.BYTES)
        private byte[] tha;
        @ProtocolField(order = 9, lengthField = "plen", type = FieldType.BYTES)
        private byte[] tpa;
    }

    // ---- WebSocket 式 ----

    @Data
    @Protocol(id = "b-ws")
    static class WsLikeFrame implements DynamicSize {
        @ProtocolField(order = 1, size = 1)
        private int mask;
        @ProtocolField(order = 2, size = 7)
        private int len7;
        @ProtocolField(order = 3, size = 16, presentIf = "len7==126")
        private int len16;
        @ProtocolField(order = 4, size = 64, type = FieldType.UNSIGNED, presentIf = "len7==127")
        private long len64;
        @ProtocolField(order = 5, type = FieldType.BYTES)
        private byte[] payload = new byte[0];

        @Override
        public long computeSize(String fieldName, FieldContext ctx) {
            if (!"payload".equals(fieldName)) {
                return -1;
            }
            long l7 = ctx.getInt("len7");
            if (l7 == 126) {
                return ctx.getInt("len16") * 8L;
            }
            if (l7 == 127) {
                return ((Number) ctx.get("len64")).longValue() * 8L;
            }
            return l7 * 8L;
        }
    }

    // ---- SCTP 式对齐填充 ----

    @Data
    @Protocol(id = "b-pad4")
    static class Pad4Frame implements DynamicSize {
        @ProtocolField(order = 1, size = 16)
        private int len;   // = 2 + payload(不含 pad,对齐用)
        @ProtocolField(order = 2, lengthField = "len", lengthAdjust = -2, type = FieldType.BYTES)
        private byte[] payload = new byte[0];
        @ProtocolField(order = 3, type = FieldType.BYTES)
        private byte[] pad = new byte[0];

        @Override
        public long computeSize(String fieldName, FieldContext ctx) {
            if (!"pad".equals(fieldName)) {
                return -1;
            }
            int payloadBytes = ((byte[]) ctx.get("payload")).length;
            int need = (4 - ((2 + payloadBytes) % 4)) % 4;
            return need * 8L;
        }
    }

    // ---- HART 式双地址形态 ----

    @Data
    @Protocol(id = "b-hart")
    static class HartLikeFrame {
        /** 分隔符:bit2(值 0x04)置 1 → 长帧 Unique ID;0 → 短帧轮询地址。
         *  位索引按声明 size(8)从 MSB 数:bit2 = delimiter[6](修复:不再按 Java int 的 32bit 视图错位)。 */
        @ProtocolField(order = 1, size = 8)
        private int delimiter = 0x02;
        @ProtocolField(order = 2, size = 8, presentIf = "delimiter[6]==0")
        private int pollAddr;
        @ProtocolField(order = 3, size = 40, type = FieldType.UNSIGNED, presentIf = "delimiter[6]==1")
        private long uniqueId;
        @ProtocolField(order = 4, size = 8)
        private int command;
    }

    // ---- XModem 式首字节选块长 ----

    @Data
    @Protocol(id = "b-xmodem")
    static class XmodemLikeFrame {
        @ProtocolField(order = 1, size = 8)
        private int start;
        @ProtocolField(order = 2, size = 8)
        private int blockNum;
        @ProtocolField(order = 3, size = 8)
        private int invBlockNum;
        @ProtocolField(order = 4, size = 1024, type = FieldType.BYTES, presentIf = "start==1")
        private byte[] block128 = new byte[128];
        @ProtocolField(order = 5, size = 8192, type = FieldType.BYTES, presentIf = "start==2")
        private byte[] block1024 = new byte[1024];
    }

    // ---- 测试 ----

    @Test
    void arpLikeDualLengthRefsRoundTrip() {
        ProtocolCodec<ArpLikeFrame> codec = new ProtocolCodec<>(ArpLikeFrame.class);
        ArpLikeFrame f = new ArpLikeFrame();
        f.setOper(1);
        f.setSha(new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66});
        f.setSpa(new byte[]{10, 0, 0, 1});
        f.setTha(new byte[6]);
        f.setTpa(new byte[]{10, 0, 0, 2});
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(8 + 6 + 4 + 6 + 4);
        ArpLikeFrame back = codec.deserialize(wire);
        assertThat(back.getSha()).containsExactly(f.getSha());
        assertThat(back.getTpa()).containsExactly(new byte[]{10, 0, 0, 2});
    }

    /** WebSocket 三档长度:直接值 / 126 逃逸 / 127 逃逸。 */
    @Test
    void websocketLikeLengthEscapeThreeTiers() {
        ProtocolCodec<WsLikeFrame> codec = new ProtocolCodec<>(WsLikeFrame.class);

        WsLikeFrame small = new WsLikeFrame();
        small.setLen7(50);
        small.setPayload(new byte[50]);
        byte[] w1 = codec.serialize(small);
        assertThat(w1).hasSize(1 + 50);

        WsLikeFrame medium = new WsLikeFrame();
        medium.setLen7(126);
        medium.setLen16(300);
        medium.setPayload(new byte[300]);
        byte[] w2 = codec.serialize(medium);
        assertThat(w2).hasSize(1 + 2 + 300);
        assertThat(w2[0]).isEqualTo((byte) 126);

        WsLikeFrame huge = new WsLikeFrame();
        huge.setLen7(127);
        huge.setLen64(5000);
        huge.setPayload(new byte[5000]);
        byte[] w3 = codec.serialize(huge);
        assertThat(w3).hasSize(1 + 8 + 5000);

        assertThat(codec.deserialize(w2).getPayload()).hasSize(300);
        assertThat(codec.deserialize(w3).getPayload()).hasSize(5000);
    }

    /** SCTP 式:长度不含 pad,pad 由 4 字节对齐动态计算(组装端须自备 pad 值)。 */
    @Test
    void padToFourByteAlignmentRoundTrip() {
        ProtocolCodec<Pad4Frame> codec = new ProtocolCodec<>(Pad4Frame.class);
        Pad4Frame f = new Pad4Frame();
        f.setPayload(new byte[]{0x11, 0x22, 0x33});   // 2+3=5 → pad 3B → 总 8
        f.setLen(5);
        f.setPad(new byte[3]);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(8);
        Pad4Frame back = codec.deserialize(wire);
        assertThat(back.getPayload()).containsExactly(0x11, 0x22, 0x33);
        assertThat(back.getPad()).hasSize(3);
    }

    /** HART 式:分隔符 bit2 切换 1B/5B 地址,两种形态各自 round-trip。 */
    @Test
    void hartLikeDualAddressForms() {
        ProtocolCodec<HartLikeFrame> codec = new ProtocolCodec<>(HartLikeFrame.class);

        HartLikeFrame shortFrame = new HartLikeFrame();
        shortFrame.setDelimiter(0x02);
        shortFrame.setPollAddr(0x0A);
        shortFrame.setCommand(0x01);
        byte[] ws = codec.serialize(shortFrame);
        assertThat(ws).containsExactly(0x02, 0x0A, 0x01);
        HartLikeFrame backS = codec.deserialize(ws);
        assertThat(backS.getPollAddr()).isEqualTo(0x0A);
        assertThat(backS.getUniqueId()).isEqualTo(0);

        HartLikeFrame longFrame = new HartLikeFrame();
        longFrame.setDelimiter(0x06);   // bit2 置 1
        longFrame.setUniqueId(0x0001020304L);
        longFrame.setCommand(0x03);
        byte[] wl = codec.serialize(longFrame);
        assertThat(wl).hasSize(7);   // delim + 5B 地址 + cmd
        HartLikeFrame backL = codec.deserialize(wl);
        assertThat(backL.getUniqueId()).isEqualTo(0x0001020304L);
        assertThat(backL.getPollAddr()).isEqualTo(0);
    }

    /** XModem 式:首字节值直接选块长(SOH=128B / STX=1024B)。 */
    @Test
    void xmodemLikeFirstByteSelectsBlockSize() {
        ProtocolCodec<XmodemLikeFrame> codec = new ProtocolCodec<>(XmodemLikeFrame.class);

        XmodemLikeFrame soh = new XmodemLikeFrame();
        soh.setStart(0x01);
        soh.setBlockNum(1);
        soh.setInvBlockNum(0xFE);
        soh.setBlock128(new byte[128]);
        assertThat(codec.serialize(soh)).hasSize(3 + 128);

        XmodemLikeFrame stx = new XmodemLikeFrame();
        stx.setStart(0x02);
        stx.setBlockNum(2);
        stx.setInvBlockNum(0xFD);
        stx.setBlock1024(new byte[1024]);
        byte[] wstx = codec.serialize(stx);
        assertThat(wstx).hasSize(3 + 1024);
        assertThat(codec.deserialize(wstx).getBlock1024()).hasSize(1024);
    }
}
