package com.netproto.protocols.real.hart;

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
 * HART 命令 0(读唯一标识符)长帧真实测试。
 * <p>
 * 帧型:{@code [FF×5 前导字节,不入帧、不建模] delimiter addr(5B) cmd byteCount data chk}。
 * <ul>
 *   <li>delimiter=0x82:主站→从站 STX 长帧,bit2(值 0x04)置 1 → 5B 长地址(Unique ID);</li>
 *   <li>byteCount 语义(依据 HCF_SPEC-127 Common Table:「Byte Count = 该字节之后、
 *       校验字节之前的字节数」;主站命令帧 = 命令数据字节数,从站应答帧 = 2 状态字节 +
 *       数据字节数。旁证:命令 11 请求 byteCount=0 且无数据)。故本帧 2B 数据 → byteCount=2;</li>
 *   <li>chk = 从 delimiter 起所有字节(含头、不含 chk 自身)逐字节 XOR。</li>
 * </ul>
 * 权威向量(全零地址、命令 0、数据 00 00,任务给定):
 * {@code 82 00 00 00 00 00 00 02 00 00 80},XOR = 0x82^0x02 = 0x80。
 * 硬断言:测试内参考 XOR 实现重算一致 + round-trip 字节级。
 */
class HartCommand0Test {

    // ---- 夹具 ----

    @Data
    @Protocol(id = "real-hart-cmd0")
    static class HartLongFrame implements Checksum {
        /** 分隔符 0x82:主站 STX 长帧(bit2=1 → 5B 长地址)。 */
        @ProtocolField(order = 1, size = 8)
        private int delimiter = 0x82;
        /** 5B 长地址(Unique ID),40bit 无符号。 */
        @ProtocolField(order = 2, size = 40, type = FieldType.UNSIGNED)
        private long address;
        /** 命令号:0 = 读唯一标识符。 */
        @ProtocolField(order = 3, size = 8)
        private int command;
        /** 字节数 = 后随数据字节数(不含校验),驱动 data 的 lengthField。 */
        @ProtocolField(order = 4, size = 8)
        private int byteCount;
        @ProtocolField(order = 5, lengthField = "byteCount", type = FieldType.BYTES)
        private byte[] data = new byte[0];
        /** 校验字节:delimiter 起所有字节 XOR(含头,不含自身)。 */
        @ProtocolField(order = 6, size = 8)
        @ChecksumField
        private int checksum;

        @Override
        public long compute(String field, byte[] serialized) {
            // 校验字段自身已被引擎置 0,XOR 整帧等价于 XOR 校验字节之前的全部字节
            int x = 0;
            for (byte b : serialized) {
                x ^= b & 0xFF;
            }
            return x;
        }
    }

    // ---- 测试 ----

    /** 命令 0 向量:82 00 00 00 00 00 00 02 00 00 80 —— 参考 XOR 重算一致 + 字节级 round-trip。 */
    @Test
    void command0AllZeroAddressVector() {
        ProtocolCodec<HartLongFrame> codec = new ProtocolCodec<>(HartLongFrame.class);
        HartLongFrame f = new HartLongFrame();
        f.setAddress(0);   // 全零 5B 长地址
        f.setCommand(0);
        f.setByteCount(2);
        f.setData(new byte[]{0x00, 0x00});

        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(
                0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x80);
        // 参考实现自证:XOR(delimiter..data 末) == 帧尾校验字节(0x82^0x02=0x80)
        assertThat(xorOf(wire, wire.length - 1)).isEqualTo(wire[wire.length - 1] & 0xFF).isEqualTo(0x80);

        HartLongFrame back = codec.deserialize(wire);
        assertThat(back.getDelimiter()).isEqualTo(0x82);
        assertThat(back.getAddress()).isZero();
        assertThat(back.getCommand()).isZero();
        assertThat(back.getByteCount()).isEqualTo(2);
        assertThat(back.getData()).containsExactly(0x00, 0x00);
        assertThat(back.getChecksum()).isEqualTo(0x80);
        assertThat(codec.serialize(back)).containsExactly(wire);
    }

    /** 非零 5B 长地址 + 非零数据:40bit 地址跨字节还原,校验随内容变化仍由参考 XOR 自证。 */
    @Test
    void nonZeroLongAddressRoundTrip() {
        ProtocolCodec<HartLongFrame> codec = new ProtocolCodec<>(HartLongFrame.class);
        HartLongFrame f = new HartLongFrame();
        f.setAddress(0x0001020304L);
        f.setCommand(0);
        f.setByteCount(2);
        f.setData(new byte[]{0x0A, 0x0B});

        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(
                0x82, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x02, 0x0A, 0x0B, 0x85);
        assertThat(xorOf(wire, wire.length - 1)).isEqualTo(wire[wire.length - 1] & 0xFF);

        HartLongFrame back = codec.deserialize(wire);
        assertThat(back.getAddress()).isEqualTo(0x0001020304L);
        assertThat(back.getData()).containsExactly(0x0A, 0x0B);
        assertThat(codec.serialize(back)).containsExactly(wire);
    }

    /** 参考校验实现:wire[0..toExclusive) 逐字节 XOR。 */
    private static int xorOf(byte[] wire, int toExclusive) {
        int x = 0;
        for (int i = 0; i < toExclusive; i++) {
            x ^= wire[i] & 0xFF;
        }
        return x;
    }
}
