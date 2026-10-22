package com.netproto.protocols.real.dlt645;

import com.netproto.annotation.ChecksumField;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.Checksum;
import com.netproto.core.FieldCodec;
import com.netproto.core.FieldContext;
import com.netproto.core.BitCursor;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DL/T 645-2007 多功能电能表通信协议真实帧测试。
 * <ul>
 *   <li>帧型:{@code [FE×n 前导] 68 A0..A5 C L DATA CS 16};</li>
 *   <li>CS = 从第一个 68H 到数据域末字节的模 256 和(含 68、不含 CS/16);</li>
 *   <li>DATA(含数据标识 DI)线上全部 +0x33 混淆 —— L2 自定义 FieldCodec 处理
 *       (custom 与 lengthField 互斥,长度从 ctx 的 len 字段取);</li>
 *   <li>读通信地址帧(规约示例形态):{@code 68 AA×6 13 00 CS 16},AA×6 为通配地址。</li>
 * </ul>
 */
class Dlt645RealTest {

    /** 数据域 +0x33/-0x33 传输混淆编解码(L2 逃生舱)。 */
    public static class Plus33DataCodec implements FieldCodec<byte[]> {
        @Override
        public byte[] read(BitCursor cursor, FieldContext ctx, int remainingBytes) {
            int len = ctx.getInt("len");
            byte[] raw = cursor.readBytes(len * 8);
            for (int i = 0; i < raw.length; i++) {
                raw[i] = (byte) ((raw[i] & 0xFF) - 0x33);
            }
            return raw;
        }

        @Override
        public void write(BitCursor cursor, FieldContext ctx, byte[] value) {
            byte[] obf = new byte[value == null ? 0 : value.length];
            for (int i = 0; i < obf.length; i++) {
                obf[i] = (byte) ((value[i] & 0xFF) + 0x33);
            }
            cursor.writeBytes(obf);
        }

        @Override
        public long sizeOf(byte[] value) {
            return value == null ? 0 : value.length * 8L;
        }
    }

    @Data
    @Protocol(id = "real-dlt645")
    static class Dlt645Frame implements Checksum {
        @ProtocolField(order = 1, size = 8)
        private int start = 0x68;
        /** 表地址 6B(BCD,低字节在前;AA×6 为通配)。 */
        @ProtocolField(order = 2, size = 48, type = FieldType.BYTES)
        private byte[] address = new byte[6];
        /** 控制码:bit7 传送方向 / bit6 从站异常 / bit5 有后续数据 / bit1..0 功能。 */
        @ProtocolField(order = 3, size = 8)
        private int ctrl;
        /** 数据域长度(线上字节数)。 */
        @ProtocolField(order = 4, size = 8)
        private int len;
        /** 数据域(DI + 数据),线上 +0x33;实体侧为明文。 */
        @ProtocolField(order = 5, type = FieldType.BYTES, custom = Plus33DataCodec.class)
        private byte[] data = new byte[0];
        @ProtocolField(order = 6, size = 8)
        @ChecksumField
        private int cs;
        @ProtocolField(order = 7, size = 8)
        private int end = 0x16;

        @Override
        public long compute(String field, byte[] serialized) {
            int sum = 0;
            for (int i = 0; i < serialized.length - 2; i++) {
                sum += serialized[i] & 0xFF;
            }
            return sum & 0xFF;
        }
    }

    /** 规约帧:读通信地址(无数据域),CS=(0x68+0xAA×6+0x13+0x00) mod 256 = 0x77。 */
    @Test
    void readAddressFrame() {
        ProtocolCodec<Dlt645Frame> codec = new ProtocolCodec<>(Dlt645Frame.class);
        Dlt645Frame f = new Dlt645Frame();
        java.util.Arrays.fill(f.getAddress(), (byte) 0xAA);
        f.setCtrl(0x13);
        f.setLen(0);
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(
                0x68, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x13, 0x00, 0x77, 0x16);

        Dlt645Frame back = codec.deserialize(wire);
        assertThat(back.getCtrl()).isEqualTo(0x13);
        assertThat(back.getCs()).isEqualTo(0x77);
    }

    /** 读数据应答:DI=00010000(正向有功总电能)+ 4B 明文数据,线上全部 +0x33。 */
    @Test
    void readDataResponseWithObfuscation() {
        ProtocolCodec<Dlt645Frame> codec = new ProtocolCodec<>(Dlt645Frame.class);
        Dlt645Frame f = new Dlt645Frame();
        byte[] addr = {(byte) 0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        f.setAddress(addr);
        f.setCtrl(0x91);   // 从站→主站,有数据,功能=读数据
        byte[] plain = {(byte) 0x00, 0x01, 0x00, 0x00,   // DI
                0x56, 0x34, 0x12, 0x00};                 // 明文数据(倒序 BCD 语义此处不展开)
        f.setData(plain);
        f.setLen(plain.length);

        byte[] wire = codec.serialize(f);
        // 数据域线上字节 = 明文逐字节 +0x33
        assertThat(wire).containsSubsequence(
                0x33, 0x34, 0x33, 0x33, 0x89, 0x67, 0x45, 0x33);
        // CS 按线上字节(混淆后)重算一致
        int sum = 0;
        for (int i = 0; i < wire.length - 2; i++) {
            sum += wire[i] & 0xFF;
        }
        assertThat(wire[wire.length - 2] & 0xFF).isEqualTo(sum & 0xFF);

        Dlt645Frame back = codec.deserialize(wire);
        assertThat(back.getData()).containsExactly(plain);   // 解回明文
        assertThat(back.getLen()).isEqualTo(8);
    }
}
