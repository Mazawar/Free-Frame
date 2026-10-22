package com.netproto.protocols.real.iec104;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IEC 60870-5-104 APCI(应用规约控制信息)真实帧测试。
 * <p>
 * APDU = {@code 68 LEN CTRL1..CTRL4 [ASDU]}。控制域 32bit 按 CTRL1 低判别位分三态:
 * <ul>
 *   <li>I 格式:CTRL1 bit0=0;发送序号 N(S) 在 CTRL1..CTRL2 的 16bit 值里「左移 1 位」
 *       —— CTRL1 bit7..bit1 = N(S) 低 7 位(N(S)=1 → CTRL1=0x02),CTRL2 = N(S) 高 8 位;
 *       CTRL3/CTRL4 同布局承载 N(R);</li>
 *   <li>S 格式:CTRL1 低 2bit=01(bit1=0,bit0=1),CTRL2=0;N(R) 与 I 帧同「左移 1 位」
 *       布局进 CTRL3/CTRL4(CTRL3 bit0=0;线上例证 N(R)=1 → CTRL3=0x02,
 *       即著名帧 {@code 68 04 01 00 02 00},与 lib60870 编码一致);</li>
 *   <li>U 格式:CTRL1 低 2bit=11;bit7..bit2 = TESTFR/STOPDT/STARTDT 的 con/act 六个功能位;
 *       CTRL2..CTRL4=0。</li>
 * </ul>
 * 建模说明:presentIf 禁止前向引用,而格式判别位位于 CTRL1 的最低 2bit(物理上最后),
 * 故 CTRL1 整字节拆成 8 个 1bit 字段无条件展开(I 帧时高 7 位即 N(S) 低 7 位,
 * U 帧时为功能位),CTRL2..CTRL4/ASDU 再按 fmtLo(=bit0)/fmtHi(=bit1) 分支三态。
 * <p>
 * 权威向量(IEC 60870-5-2 / 60870-5-104 规约著名帧,任务给定):
 * STARTDT act = 68 04 07 00 00 00;STARTDT con = 68 04 0B 00 00 00;
 * TESTFR act = 68 04 43 00 00 00;S 帧(N(R)=0)= 68 04 01 00 00 00;
 * I 帧 N(S)=0,N(R)=0 = 68 04 00 00 00 00;I 帧 N(S)=1 = 68 04 02 00 00 00。
 */
class Iec104ApciTest {

    @Data
    @Protocol(id = "real-iec104-apci")
    static class Apci {
        @ProtocolField(order = 1, size = 8)
        private int start = 0x68;
        /** APDU 长度 = 控制域 4 字节 + ASDU(U/S 帧恒 4;驱动 ASDU 的 lengthField)。 */
        @ProtocolField(order = 2, size = 8)
        private int length = 4;

        // ---- CTRL1(控制域第 1 字节,MSB→LSB 逐位无条件展开)----
        // I 帧中 bit7..bit1 属于 N(S) 低 7 位;U 帧中 bit7..bit2 为功能位;S 帧全 0
        @ProtocolField(order = 3, size = 1)
        private int testfrCon;   // bit7(0x80):U 帧 TESTFR con
        @ProtocolField(order = 4, size = 1)
        private int testfrAct;   // bit6(0x40):U 帧 TESTFR act
        @ProtocolField(order = 5, size = 1)
        private int stopdtCon;   // bit5(0x20):U 帧 STOPDT con
        @ProtocolField(order = 6, size = 1)
        private int stopdtAct;   // bit4(0x10):U 帧 STOPDT act
        @ProtocolField(order = 7, size = 1)
        private int startdtCon;  // bit3(0x08):U 帧 STARTDT con
        @ProtocolField(order = 8, size = 1)
        private int startdtAct;  // bit2(0x04):U 帧 STARTDT act
        /** bit1(0x02):U 帧=1;S 帧=0;I 帧 = N(S) bit0(三态判别的高位)。 */
        @ProtocolField(order = 9, size = 1)
        private int fmtHi;
        /** bit0(0x01):I 帧=0;S/U 帧=1(三态判别的低位;S/I 格式区分只看 CTRL1 低 2bit)。 */
        @ProtocolField(order = 10, size = 1)
        private int fmtLo;

        // ---- CTRL2(fmtLo==0 → I)----
        @ProtocolField(order = 11, size = 8, presentIf = "fmtLo==0")
        private int sendSeqHi8;   // I 帧:N(S) bit7..14
        @ProtocolField(order = 12, size = 8, presentIf = "fmtLo==1")
        private int ctrl2Zero;    // S/U 帧:恒 0

        // ---- CTRL3(fmtLo==0 或 fmtHi==0 → I/S 共用 N(R) 布局;U 帧恒 0)----
        @ProtocolField(order = 13, size = 7, presentIf = "!fmtLo||!fmtHi")
        private int recvSeqLo7;   // I/S 帧:N(R) bit0..6(CTRL3 bit7..bit1)
        @ProtocolField(order = 14, size = 1, presentIf = "!fmtLo||!fmtHi")
        private int ctrl3Lsb;     // CTRL3 bit0:I/S 帧恒 0(N(R) 左移 1 位布局的空出位)
        @ProtocolField(order = 15, size = 8, presentIf = "fmtLo==1&&fmtHi==1")
        private int ctrl3Zero;    // U 帧:恒 0

        // ---- CTRL4 ----
        @ProtocolField(order = 16, size = 8, presentIf = "!fmtLo||!fmtHi")
        private int recvSeqHi8;   // I/S 帧:N(R) bit7..14
        @ProtocolField(order = 17, size = 8, presentIf = "fmtLo==1&&fmtHi==1")
        private int ctrl4Zero;    // U 帧:恒 0

        // ---- ASDU:字节数 = APDU 长度 - 4(APCI 控制域)----
        @ProtocolField(order = 18, lengthField = "length", lengthAdjust = -4, type = FieldType.BYTES)
        private byte[] asdu = new byte[0];

        /** I 帧发送序号 N(S):CTRL1 bit7..bit1(低 7 位,「16bit 控制域左移 1 位」)+ sendSeqHi8。 */
        public int sendSeq() {
            int lo7 = (testfrCon << 6) | (testfrAct << 5) | (stopdtCon << 4)
                    | (stopdtAct << 3) | (startdtCon << 2) | (startdtAct << 1) | fmtHi;
            return lo7 | (sendSeqHi8 << 7);
        }

        /** S/I 帧接收序号 N(R):recvSeqLo7(CTRL3 bit7..bit1)+ recvSeqHi8(CTRL4),同为左移 1 位布局。 */
        public int recvSeq() {
            return recvSeqLo7 | (recvSeqHi8 << 7);
        }
    }

    // ---- 测试 ----

    /** U 帧三向量:STARTDT act/con 与 TESTFR act(规约著名帧),字节级断言 + round-trip。 */
    @Test
    void uFrameVectors() {
        ProtocolCodec<Apci> codec = new ProtocolCodec<>(Apci.class);

        Apci startdtAct = new Apci();
        startdtAct.setStartdtAct(1);
        startdtAct.setFmtHi(1);
        startdtAct.setFmtLo(1);
        assertThat(codec.serialize(startdtAct))
                .containsExactly(0x68, 0x04, 0x07, 0x00, 0x00, 0x00);

        Apci startdtCon = new Apci();
        startdtCon.setStartdtCon(1);
        startdtCon.setFmtHi(1);
        startdtCon.setFmtLo(1);
        assertThat(codec.serialize(startdtCon))
                .containsExactly(0x68, 0x04, 0x0B, 0x00, 0x00, 0x00);

        Apci testfrAct = new Apci();
        testfrAct.setTestfrAct(1);
        testfrAct.setFmtHi(1);
        testfrAct.setFmtLo(1);
        assertThat(codec.serialize(testfrAct))
                .containsExactly(0x68, 0x04, 0x43, 0x00, 0x00, 0x00);

        // 反序列化识别 U 格式并还原功能位;I/S 专属字段被跳过(保持默认 0)
        Apci back = codec.deserialize(new byte[]{0x68, 0x04, 0x0B, 0x00, 0x00, 0x00});
        assertThat(back.getFmtLo()).isEqualTo(1);
        assertThat(back.getFmtHi()).isEqualTo(1);
        assertThat(back.getStartdtCon()).isEqualTo(1);
        assertThat(back.getStartdtAct()).isZero();
        assertThat(back.getRecvSeqLo7()).isZero();
        assertThat(codec.serialize(back)).containsExactly(0x68, 0x04, 0x0B, 0x00, 0x00, 0x00);
    }

    /** S 帧向量 68 04 01 00 00 00;N(R) 跨 CTRL3/CTRL4 拼装(=0 与 =300 两档)。 */
    @Test
    void sFrameVectorAndRecvSeq() {
        ProtocolCodec<Apci> codec = new ProtocolCodec<>(Apci.class);

        Apci s = new Apci();
        s.setFmtLo(1);     // 低 2bit=01(bit1=0,bit0=1)
        assertThat(codec.serialize(s)).containsExactly(0x68, 0x04, 0x01, 0x00, 0x00, 0x00);

        Apci back = codec.deserialize(new byte[]{0x68, 0x04, 0x01, 0x00, 0x00, 0x00});
        assertThat(back.getFmtLo()).isEqualTo(1);
        assertThat(back.getFmtHi()).isZero();
        assertThat(back.getCtrl3Lsb()).isZero();
        assertThat(back.recvSeq()).isZero();
        assertThat(codec.serialize(back)).containsExactly(0x68, 0x04, 0x01, 0x00, 0x00, 0x00);

        // N(R)=300(>127,跨 CTRL3 低 7 位与 CTRL4):CTRL3=(300&0x7F)<<1=0x58,CTRL4=2
        Apci s300 = new Apci();
        s300.setFmtLo(1);
        s300.setRecvSeqLo7(300 & 0x7F);
        s300.setRecvSeqHi8(300 >> 7);
        byte[] w = codec.serialize(s300);
        assertThat(w).containsExactly(0x68, 0x04, 0x01, 0x00, 0x58, 0x02);
        assertThat(codec.deserialize(w).recvSeq()).isEqualTo(300);
    }

    /** I 帧向量:N(S)=0/N(R)=0 与 N(S)=1;发送序号按「左移 1 位」布局还原(sendSeq=1 读回 1)。 */
    @Test
    void iFrameSequenceNumbers() {
        ProtocolCodec<Apci> codec = new ProtocolCodec<>(Apci.class);

        byte[] w0 = codec.serialize(iFrame(0, 0));
        assertThat(w0).containsExactly(0x68, 0x04, 0x00, 0x00, 0x00, 0x00);

        byte[] w1 = codec.serialize(iFrame(1, 0));
        assertThat(w1).containsExactly(0x68, 0x04, 0x02, 0x00, 0x00, 0x00);

        Apci back1 = codec.deserialize(w1);
        assertThat(back1.getFmtLo()).isZero();     // CTRL1 bit0=0 → I 格式
        assertThat(back1.sendSeq()).isEqualTo(1);  // 序号还原:N(S)=1 → CTRL1=0x02
        assertThat(back1.recvSeq()).isZero();
        assertThat(codec.serialize(back1)).containsExactly(0x68, 0x04, 0x02, 0x00, 0x00, 0x00);

        // N(S)=300:低 7 位 0x2C 进 CTRL1(<<1 = 0x58),高 8 位进 CTRL2(0x02)
        byte[] w300 = codec.serialize(iFrame(300, 0));
        assertThat(w300).containsExactly(0x68, 0x04, 0x58, 0x02, 0x00, 0x00);
        assertThat(codec.deserialize(w300).sendSeq()).isEqualTo(300);
    }

    /** I 帧带 ASDU:APDU 长度 = 4 + ASDU 字节数(lengthField="length" + lengthAdjust=-4 驱动)。 */
    @Test
    void iFrameWithAsdu() {
        ProtocolCodec<Apci> codec = new ProtocolCodec<>(Apci.class);
        Apci f = iFrame(2, 1);
        f.setLength(6);
        f.setAsdu(new byte[]{0x01, 0x02});
        byte[] wire = codec.serialize(f);
        // CTRL1=0x04(N(S)=2<<1),CTRL3=0x02(N(R)=1<<1),ASDU=01 02
        assertThat(wire).containsExactly(0x68, 0x06, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02);

        Apci back = codec.deserialize(wire);
        assertThat(back.sendSeq()).isEqualTo(2);
        assertThat(back.recvSeq()).isEqualTo(1);
        assertThat(back.getAsdu()).containsExactly(0x01, 0x02);
        assertThat(back.getLength()).isEqualTo(6);
        assertThat(codec.serialize(back)).containsExactly(wire);
    }

    /** 组装 I 帧:N(S)/N(R) 15bit 按「左移 1 位」布局拆进 CTRL1..CTRL4(CTRL3 bit0=0)。 */
    private static Apci iFrame(int sendSeq, int recvSeq) {
        Apci f = new Apci();
        f.setTestfrCon((sendSeq >> 6) & 1);
        f.setTestfrAct((sendSeq >> 5) & 1);
        f.setStopdtCon((sendSeq >> 4) & 1);
        f.setStopdtAct((sendSeq >> 3) & 1);
        f.setStartdtCon((sendSeq >> 2) & 1);
        f.setStartdtAct((sendSeq >> 1) & 1);
        f.setFmtHi(sendSeq & 1);                 // N(S) bit0
        f.setSendSeqHi8((sendSeq >> 7) & 0xFF);
        f.setRecvSeqLo7(recvSeq & 0x7F);
        f.setCtrl3Lsb(0);
        f.setRecvSeqHi8((recvSeq >> 7) & 0xFF);
        return f;
    }
}
