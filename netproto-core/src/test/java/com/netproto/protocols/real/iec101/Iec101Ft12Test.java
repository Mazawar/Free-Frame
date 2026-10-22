package com.netproto.protocols.real.iec101;

import com.netproto.annotation.ChecksumField;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.Checksum;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IEC 60870-5-101 FT1.2 帧真实测试(定长帧 + 可变帧)。
 * <ul>
 *   <li>定长帧:{@code 10 C A CS 16},CS = (C + A) mod 256,不含起始/结束字符。
 *       权威向量(链路复位请求,链路地址 1,任务给定):{@code 10 40 01 41 16},
 *       CS = (0x40 + 0x01) mod 256 = 0x41;</li>
 *   <li>可变帧:{@code 68 L L 68 C A DATA... CS 16},长度双写一致;
 *       L = 控制域(1) + 地址(1) + 用户数据字节数;CS 按任务口径 =
 *       从第一个 0x68 起累加到 CS 前一字节(即 68 L L 68 C A DATA)mod 256。
 *       自构造向量:数据 33 34 → {@code 68 04 04 68 10 01 33 34 50 16},
 *       CS = (0x68+0x04+0x04+0x68+0x10+0x01+0x33+0x34) mod 256 = 0x50,
 *       测试内用参考实现重算并断言一致。</li>
 *   <li>帧尾 CS 用 Checksum 钩子 + @ChecksumField 实现(引擎先置 0,算完回写)。</li>
 * </ul>
 */
class Iec101Ft12Test {

    // ---- 夹具 ----

    /** FT1.2 定长帧:10 C A CS 16(链路层单字符服务,无用户数据)。 */
    @Data
    @Protocol(id = "real-iec101-fixed")
    static class Ft12FixedFrame implements Checksum {
        @ProtocolField(order = 1, size = 8)
        private int start = 0x10;
        @ProtocolField(order = 2, size = 8)
        private int ctrl;
        @ProtocolField(order = 3, size = 8)
        private int addr;
        @ProtocolField(order = 4, size = 8)
        @ChecksumField
        private int cs;
        @ProtocolField(order = 5, size = 8)
        private int end = 0x16;

        @Override
        public long compute(String field, byte[] serialized) {
            // 定长帧 CS = (控制域 C + 链路地址 A) mod 256,不含起始字符 0x10/结束字符 0x16
            return ((serialized[1] & 0xFF) + (serialized[2] & 0xFF)) & 0xFF;
        }
    }

    /** FT1.2 可变帧:68 L L 68 C A DATA CS 16(L 双写,DATA 长度 = L - 2)。 */
    @Data
    @Protocol(id = "real-iec101-var")
    static class Ft12VariableFrame implements Checksum {
        @ProtocolField(order = 1, size = 8)
        private int start1 = 0x68;
        /** L = 控制域(1) + 地址(1) + 用户数据字节数(此处 4)。 */
        @ProtocolField(order = 2, size = 8)
        private int len;
        /** 长度双写(FT1.2 冗余校验),应与 len 一致。 */
        @ProtocolField(order = 3, size = 8)
        private int lenRepeat;
        @ProtocolField(order = 4, size = 8)
        private int start2 = 0x68;
        @ProtocolField(order = 5, size = 8)
        private int ctrl;
        @ProtocolField(order = 6, size = 8)
        private int addr;
        @ProtocolField(order = 7, lengthField = "len", lengthAdjust = -2, type = FieldType.BYTES)
        private byte[] data = new byte[0];
        @ProtocolField(order = 8, size = 8)
        @ChecksumField
        private int cs;
        @ProtocolField(order = 9, size = 8)
        private int end = 0x16;

        @Override
        public long compute(String field, byte[] serialized) {
            // 任务口径:CS = 从第一个 0x68 起累加到 CS 前一字节(末两字节 = CS(已置0)+ 0x16)
            int sum = 0;
            for (int i = 0; i < serialized.length - 2; i++) {
                sum += serialized[i] & 0xFF;
            }
            return sum & 0xFF;
        }
    }

    // ---- 测试 ----

    /** 定长帧向量(链路复位,地址 1):10 40 01 41 16;参考实现重算 CS 一致。 */
    @Test
    void fixedFrameResetLinkVector() {
        ProtocolCodec<Ft12FixedFrame> codec = new ProtocolCodec<>(Ft12FixedFrame.class);
        Ft12FixedFrame f = new Ft12FixedFrame();
        f.setCtrl(0x40);   // 链路复位请求 FCB=0,FCV=0
        f.setAddr(0x01);
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(0x10, 0x40, 0x01, 0x41, 0x16);
        // 参考实现:CS = (C + A) mod 256
        assertThat(((wire[1] & 0xFF) + (wire[2] & 0xFF)) & 0xFF).isEqualTo(wire[3] & 0xFF).isEqualTo(0x41);

        Ft12FixedFrame back = codec.deserialize(wire);
        assertThat(back.getCtrl()).isEqualTo(0x40);
        assertThat(back.getAddr()).isEqualTo(1);
        assertThat(back.getCs()).isEqualTo(0x41);
        assertThat(codec.serialize(back)).containsExactly(wire);
    }

    /** 可变帧向量(2 字节用户数据 33 34):双写长度一致,CS 从第一个 68 累加(参考实现自证 0x50)。 */
    @Test
    void variableFrameWithUserData() {
        ProtocolCodec<Ft12VariableFrame> codec = new ProtocolCodec<>(Ft12VariableFrame.class);
        Ft12VariableFrame f = new Ft12VariableFrame();
        f.setCtrl(0x10);
        f.setAddr(0x01);
        f.setData(new byte[]{0x33, 0x34});
        f.setLen(4);        // L = 控制域(1) + 地址(1) + 数据(2)
        f.setLenRepeat(4);  // FT1.2 长度双写

        byte[] wire = codec.serialize(f);
        // 参考实现:CS = 前 8 字节(第一个 68 到 CS 前)累加 mod 256
        int ref = 0;
        for (int i = 0; i < 8; i++) {
            ref += wire[i] & 0xFF;
        }
        assertThat(wire).containsExactly(
                0x68, 0x04, 0x04, 0x68, 0x10, 0x01, 0x33, 0x34, ref & 0xFF, 0x16);
        assertThat(ref & 0xFF).isEqualTo(0x50);

        Ft12VariableFrame back = codec.deserialize(wire);
        assertThat(back.getLen()).isEqualTo(back.getLenRepeat()).isEqualTo(4);
        assertThat(back.getData()).containsExactly(0x33, 0x34);
        assertThat(back.getCs()).isEqualTo(0x50);
        assertThat(codec.serialize(back)).containsExactly(wire);
    }
}
