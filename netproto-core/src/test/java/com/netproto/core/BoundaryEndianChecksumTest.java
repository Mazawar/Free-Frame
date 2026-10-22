package com.netproto.core;

import com.netproto.annotation.ChecksumField;
import com.netproto.annotation.Endian;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 能力边界测试:端序与校验族。
 * <ul>
 *   <li>同帧混合端序(PROFINET/CANopen/Modbus 寄存器常见)—— 逐字段 endian 声明,应可用;</li>
 *   <li>FLOAT 的 LITTLE 端序(Modbus 32bit 浮点最常见形态)—— 已修复:读写均应用 endian;</li>
 *   <li>Modbus RTU:字节计数循环 + 帧尾 CRC16(低字节在前)—— Checksum 钩子 + 预交换值可解
 *       (回写端序已修复,亦可将字段声明 LITTLE 由引擎交换);</li>
 *   <li>双校验和:两区域独立可用;后者覆盖前者校验值时读到 0(机制限制)。</li>
 * </ul>
 */
class BoundaryEndianChecksumTest {

    // ---- 夹具 ----

    /** 同帧 BE u16 + LE u16 + LE u32(PROFINET 式混合)。 */
    @Data
    @Protocol(id = "b-mixed-endian")
    static class MixedEndianFrame {
        @ProtocolField(order = 1, size = 16)
        private int beU16;
        @ProtocolField(order = 2, size = 16, endian = Endian.LITTLE)
        private int leU16;
        @ProtocolField(order = 3, size = 32, endian = Endian.LITTLE)
        private long leU32;
    }

    /** LE 浮点(Modbus 寄存器形态)。 */
    @Data
    @Protocol(id = "b-le-float")
    static class LeFloatFrame {
        @ProtocolField(order = 1, size = 32, endian = Endian.LITTLE)
        private float value;
    }

    /** 校验和字段声明 LITTLE:解码按 LE 读、回写固定 MSB-first —— 现状特征用。 */
    @Data
    @Protocol(id = "b-le-cksum")
    static class LeChecksumFrame implements Checksum {
        @ProtocolField(order = 1, size = 8)
        private int cmd;
        @ProtocolField(order = 2, size = 16, endian = Endian.LITTLE)
        @ChecksumField
        private int crc;

        @Override
        public long compute(String field, byte[] serialized) {
            // 恒定返回 0x1234,观察回写位序
            return 0x1234;
        }
    }

    /** Modbus RTU 读保持寄存器响应(字节计数驱动 + 帧尾 CRC16)。 */
    @Data
    @Protocol(id = "b-modbus")
    static class ModbusRtuReadResp implements Checksum {
        @ProtocolField(order = 1, size = 8)
        private int addr;
        @ProtocolField(order = 2, size = 8)
        private int func = 3;
        @ProtocolField(order = 3, size = 8)
        private int byteCount;
        @ProtocolField(order = 4, type = FieldType.LIST, countField = "byteCount",
                countUnit = com.netproto.annotation.CountUnit.BYTES, elementClass = Reg16.class)
        private List<Reg16> regs = new ArrayList<>();
        @ProtocolField(order = 5, size = 16)
        @ChecksumField
        private int crc;

        @Override
        public long compute(String field, byte[] serialized) {
            if (!"crc".equals(field)) {
                return -1;
            }
            long crc = crc16Modbus(serialized, 0, serialized.length - 2);
            // 线路序 = 低字节在前;引擎回写固定 MSB-first → 预交换
            return ((crc & 0xFF) << 8) | ((crc >> 8) & 0xFF);
        }
    }

    @Data
    @Protocol(id = "b-modbus-reg")
    static class Reg16 {
        @ProtocolField(order = 1, size = 16)
        private int value;
    }

    /** 双校验和:头部反码和 + 尾部累加和(区域独立)。 */
    @Data
    @Protocol(id = "b-dual-cksum")
    static class DualChecksumFrame implements Checksum {
        @ProtocolField(order = 1, size = 8)
        private int len;
        @ProtocolField(order = 2, size = 16)
        @ChecksumField
        private int hdrSum;
        @ProtocolField(order = 3, lengthField = "len", lengthAdjust = -4, type = FieldType.BYTES)
        private byte[] body = new byte[0];
        @ProtocolField(order = 4, size = 8)
        @ChecksumField
        private int tailSum;

        @Override
        public long compute(String field, byte[] serialized) {
            if ("hdrSum".equals(field)) {
                long s = 0;
                for (int i = 0; i < 3; i++) {
                    s += serialized[i] & 0xFF;
                }
                return s & 0xFFFF;
            }
            if ("tailSum".equals(field)) {
                long s = 0;
                for (int i = 3; i < serialized.length - 1; i++) {
                    s += serialized[i] & 0xFF;
                }
                return s & 0xFF;
            }
            return -1;
        }
    }

    // ---- 测试 ----

    @Test
    void mixedEndianRoundTrips() {
        ProtocolCodec<MixedEndianFrame> codec = new ProtocolCodec<>(MixedEndianFrame.class);
        MixedEndianFrame f = new MixedEndianFrame();
        f.setBeU16(0x1234);
        f.setLeU16(0x5678);
        f.setLeU32(0x0A0B0C0DL);
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(
                0x12, 0x34,                       // BE
                0x78, 0x56,                       // LE
                0x0D, 0x0C, 0x0B, 0x0A);          // LE 32
        MixedEndianFrame back = codec.deserialize(wire);
        assertThat(back.getBeU16()).isEqualTo(0x1234);
        assertThat(back.getLeU16()).isEqualTo(0x5678);
        assertThat(back.getLeU32()).isEqualTo(0x0A0B0C0DL);
    }

    /** LE 浮点(Modbus 寄存器形态)round-trip:修复后读写均应用 endian。 */
    @Test
    void littleEndianFloatRoundTrips() {
        ProtocolCodec<LeFloatFrame> codec = new ProtocolCodec<>(LeFloatFrame.class);
        // 1.5f BE = 0x3FC00000;LE 线路字节序 = 00 00 C0 3F
        byte[] leWire = {0x00, 0x00, (byte) 0xC0, 0x3F};
        LeFloatFrame back = codec.deserialize(leWire);
        assertThat(back.getValue()).isEqualTo(1.5f);
        // 编码方向同样输出 LE 字节序
        LeFloatFrame f = new LeFloatFrame();
        f.setValue(1.5f);
        assertThat(codec.serialize(f)).containsExactly(0x00, 0x00, (byte) 0xC0, 0x3F);
    }

    /**
     * @ChecksumField 回写应用字段 endian(修复:此前固定 MSB-first 忽略 LITTLE)。
     * 编码:compute=0x1234 → LE 写出 34 12;解码:34 12 按 LE 读回 0x1234 —— 编解码对称。
     */
    @Test
    void checksumWritebackHonorsFieldEndian() {
        ProtocolCodec<LeChecksumFrame> codec = new ProtocolCodec<>(LeChecksumFrame.class);
        LeChecksumFrame f = new LeChecksumFrame();
        f.setCmd(0x01);
        byte[] wire = codec.serialize(f);
        assertThat(wire).containsExactly(0x01, 0x34, 0x12);
        LeChecksumFrame back = codec.deserialize(wire);
        assertThat(back.getCrc()).isEqualTo(0x1234);
    }

    /** CRC-16/MODBUS 标准校验向量:"123456789" → 0x4B37。 */
    @Test
    void crc16ModbusReferenceVector() {
        byte[] check = "123456789".getBytes();
        assertThat(crc16Modbus(check, 0, check.length)).isEqualTo(0x4B37);
    }

    /** Modbus RTU 响应整帧:计数字节换算 + 帧尾 CRC(低前)round-trip。 */
    @Test
    void modbusRtuFrameRoundTrip() {
        ProtocolCodec<ModbusRtuReadResp> codec = new ProtocolCodec<>(ModbusRtuReadResp.class);
        ModbusRtuReadResp f = new ModbusRtuReadResp();
        f.setAddr(0x01);
        f.setFunc(0x03);
        Reg16 r1 = new Reg16();
        r1.setValue(0x0224);   // 548(温度×10 的典型编码)
        Reg16 r2 = new Reg16();
        r2.setValue(0x0064);
        f.setRegs(new ArrayList<>(List.of(r1, r2)));
        f.setByteCount(4);     // 2 寄存器 × 2B

        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(9);   // addr+func+bc+4B 数据+2B CRC

        // CRC 覆盖前面 7 字节,重算核对(低字节在前)
        long expect = crc16Modbus(wire, 0, 7);
        assertThat(wire[7] & 0xFF).isEqualTo(expect & 0xFF);
        assertThat(wire[8] & 0xFF).isEqualTo((expect >> 8) & 0xFF);

        ModbusRtuReadResp back = codec.deserialize(wire);
        assertThat(back.getRegs()).hasSize(2);
        assertThat(back.getRegs().get(0).getValue()).isEqualTo(0x0224);
        assertThat(back.getByteCount()).isEqualTo(4);
        // 计数字段声明 0 时自动回填(引擎特性)
        ModbusRtuReadResp auto = new ModbusRtuReadResp();
        auto.setAddr(1);
        auto.setFunc(3);
        auto.setRegs(new ArrayList<>(List.of(r1, r2)));
        assertThat(codec.serialize(auto)).containsExactly(wire);
    }

    /** 双校验和(区域独立)round-trip 可用。 */
    @Test
    void dualIndependentChecksumsWork() {
        ProtocolCodec<DualChecksumFrame> codec = new ProtocolCodec<>(DualChecksumFrame.class);
        DualChecksumFrame f = new DualChecksumFrame();
        byte[] body = {0x0A, 0x0B, 0x0C};
        f.setBody(body);
        f.setLen(body.length + 4);   // 整帧 7B:len+hdrSum(2)+body(3)+tailSum(1)
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(7);
        assertThat(wire[2] & 0xFF).isEqualTo(7 + 0 + 0);         // hdrSum(16bit BE)低字节: len(7)+hdrSum零区(0)
        assertThat(wire[6] & 0xFF).isEqualTo(0x0A + 0x0B + 0x0C); // 33
        DualChecksumFrame back = codec.deserialize(wire);
        assertThat(back.getBody()).containsExactly(body);
    }

    /** CRC-16/MODBUS(poly 0x8005, init 0xFFFF, RefIn/RefOut=true, XorOut=0)。 */
    static long crc16Modbus(byte[] data, int off, int len) {
        int crc = 0xFFFF;
        for (int i = 0; i < len; i++) {
            crc ^= data[off + i] & 0xFF;
            for (int b = 0; b < 8; b++) {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xA001 : crc >> 1;   // 0xA001 = reverse(0x8005)
            }
        }
        return crc & 0xFFFF;
    }
}
