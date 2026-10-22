package com.netproto.protocols.real.isotp;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ISO-TP(ISO 15765-2)半字节 PCI 真实帧测试(SF/FF/FC/CF 四类实体)。
 * <p>
 * PCI 在首字节:高半字节 = 帧类型(SF=0/FF=1/CF=2/FC=3),低半字节含义随类型:
 * SF = 4bit 长度(经典 CAN ≤7);FF = 12bit 长度跨字节(低半字节为高位 + 次整字节为低 8 位);
 * CF = 4bit 序号(1..15 循环,0x0F 后跳过 0);FC 帧型后接 4bit 流状态 + BS/STmin 各 1 字节。
 * <p>
 * 权威向量(任务给定):
 * SF(2 字节载荷)= {@code 02 10 01};FC(CTS)= {@code 30 00 00};
 * CF#1 = {@code 21 11 22 33 44 55 66 77};FF(100 字节消息)= {@code 10 64 11 22 33 44 55 66}
 * (12bit 长度 = 0x064 = 100)。
 */
class IsoTpFrameTest {

    // ---- 夹具 ----

    /** 单帧 SF:PCI = [type=0(4bit)][SF_DL(4bit)],后接 ≤7 字节数据。 */
    @Data
    @Protocol(id = "real-isotp-sf")
    static class SingleFrame {
        @ProtocolField(order = 1, size = 4)
        private int frameType;   // 高半字节:0 = SF
        @ProtocolField(order = 2, size = 4)
        private int dl;          // 低半字节:SF_DL(经典 CAN ≤ 7;CAN-FD 0x00 逃逸形态不建模)
        @ProtocolField(order = 3, lengthField = "dl", type = FieldType.BYTES)
        private byte[] data = new byte[0];
    }

    /** 首帧 FF:PCI = [type=1(4bit)][FF_DL 高 4bit],次字节 = FF_DL 低 8bit(12bit 跨字节拼装),固定携带前 6 字节。 */
    @Data
    @Protocol(id = "real-isotp-ff")
    static class FirstFrame {
        @ProtocolField(order = 1, size = 4)
        private int frameType = 1;
        @ProtocolField(order = 2, size = 4)
        private int lenHi;    // FF_DL bit11..8(首字节低半字节)
        @ProtocolField(order = 3, size = 8)
        private int lenLo;    // FF_DL bit7..0(次整字节)
        @ProtocolField(order = 4, size = 48, type = FieldType.BYTES)
        private byte[] data = new byte[6];   // FF 固定携带报文前 6 字节(48bit)
    }

    /** 流控帧 FC:PCI = [type=3(4bit)][FS(4bit)],后接块大小 BS 与最小间隔时间 STmin。 */
    @Data
    @Protocol(id = "real-isotp-fc")
    static class FlowControlFrame {
        @ProtocolField(order = 1, size = 4)
        private int frameType = 3;
        @ProtocolField(order = 2, size = 4)
        private int flowStatus;   // 0 = Continue To Send(CTS);1 = Wait;2 = Overflow
        @ProtocolField(order = 3, size = 8)
        private int blockSize;
        @ProtocolField(order = 4, size = 8)
        private int stMin;
    }

    /** 连续帧 CF:PCI = [type=2(4bit)][SN(4bit)],序号 1..15 循环;非末帧固定 7 字节数据。 */
    @Data
    @Protocol(id = "real-isotp-cf")
    static class ConsecutiveFrame {
        @ProtocolField(order = 1, size = 4)
        private int frameType = 2;
        @ProtocolField(order = 2, size = 4)
        private int seqNum;   // SN:首个 CF=1,递增至 0x0F 后回绕(0 被跳过)
        @ProtocolField(order = 3, size = 56, type = FieldType.BYTES)
        private byte[] data = new byte[7];
    }

    // ---- 测试 ----

    /** SF 向量:02 10 01 —— 高半字节 type=0、低半字节长度=2,载荷 2 字节逐字节还原。 */
    @Test
    void singleFrameVector() {
        ProtocolCodec<SingleFrame> codec = new ProtocolCodec<>(SingleFrame.class);
        SingleFrame f = new SingleFrame();
        f.setFrameType(0);
        f.setDl(2);
        f.setData(new byte[]{0x10, 0x01});
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(0x02, 0x10, 0x01);

        SingleFrame back = codec.deserialize(wire);
        assertThat(back.getFrameType()).isZero();
        assertThat(back.getDl()).isEqualTo(2);
        assertThat(back.getData()).containsExactly(0x10, 0x01);
        assertThat(codec.serialize(back)).containsExactly(wire);
    }

    /** FF 向量:10 64 11 22 33 44 55 66 —— 12bit 长度跨字节拼装(lenHi 半字节<<8 | lenLo)= 100。 */
    @Test
    void firstFrame12BitLengthAssembly() {
        ProtocolCodec<FirstFrame> codec = new ProtocolCodec<>(FirstFrame.class);
        FirstFrame f = new FirstFrame();
        f.setLenHi(0x0);   // FF_DL = 0x064 = 100
        f.setLenLo(0x64);
        f.setData(new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66});
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(0x10, 0x64, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        FirstFrame back = codec.deserialize(wire);
        assertThat(back.getFrameType()).isEqualTo(1);
        assertThat((back.getLenHi() << 8) | back.getLenLo()).isEqualTo(100);
        assertThat(back.getData()).containsExactly(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        // 高 4 位非零档:FF_DL = 0x0ABC = 2748 → PCI 两字节 1A BC
        FirstFrame big = new FirstFrame();
        big.setLenHi(0x0A);
        big.setLenLo(0xBC);
        big.setData(new byte[6]);
        byte[] wireBig = codec.serialize(big);
        assertThat(wireBig).containsExactly(0x1A, (byte) 0xBC, 0, 0, 0, 0, 0, 0);
        FirstFrame backBig = codec.deserialize(wireBig);
        assertThat((backBig.getLenHi() << 8) | backBig.getLenLo()).isEqualTo(0x0ABC);
    }

    /** FC 向量:30 00 00 —— type=3、流状态 CTS(0)、块大小 0(不限)、STmin 0。 */
    @Test
    void flowControlCtsVector() {
        ProtocolCodec<FlowControlFrame> codec = new ProtocolCodec<>(FlowControlFrame.class);
        FlowControlFrame f = new FlowControlFrame();
        f.setFlowStatus(0);
        f.setBlockSize(0);
        f.setStMin(0);
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(0x30, 0x00, 0x00);

        FlowControlFrame back = codec.deserialize(wire);
        assertThat(back.getFrameType()).isEqualTo(3);
        assertThat(back.getFlowStatus()).isZero();
        assertThat(back.getBlockSize()).isZero();
        assertThat(back.getStMin()).isZero();
        assertThat(codec.serialize(back)).containsExactly(wire);
    }

    /** CF 向量:21 11 22 33 44 55 66 77 —— type=2、4bit 序号 SN=1;序号 15(0x0F)回绕档验证。 */
    @Test
    void consecutiveFrameSequenceNumber() {
        ProtocolCodec<ConsecutiveFrame> codec = new ProtocolCodec<>(ConsecutiveFrame.class);
        ConsecutiveFrame f = new ConsecutiveFrame();
        f.setSeqNum(1);
        f.setData(new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77});
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(0x21, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77);

        ConsecutiveFrame back = codec.deserialize(wire);
        assertThat(back.getFrameType()).isEqualTo(2);
        assertThat(back.getSeqNum()).isEqualTo(1);
        assertThat(back.getData()).containsExactly(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77);
        assertThat(codec.serialize(back)).containsExactly(wire);

        // SN 回绕档:0x0F → 首字节 0x2F,读回仍为 15
        f.setSeqNum(15);
        byte[] w15 = codec.serialize(f);
        assertThat(w15[0]).isEqualTo((byte) 0x2F);
        assertThat(codec.deserialize(w15).getSeqNum()).isEqualTo(15);
    }
}
