package com.netproto.protocols.real.modbus;

import com.netproto.annotation.ChecksumField;
import com.netproto.annotation.Endian;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.Checksum;
import com.netproto.core.FieldContext;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Modbus RTU 真实帧测试。
 * <ul>
 *   <li>读保持寄存器请求:规约/维基经典帧(slave 0x11,start=107,qty=3):
 *       {@code 11 03 00 6B 00 03 76 87}(CRC-16/MODBUS 低字节在前);</li>
 *   <li>读响应:byteCount(字节数驱动)× u16 寄存器;</li>
 *   <li>CRC 用 Checksum 钩子 + 字段 endian=LITTLE(引擎回写应用端序,无需手工预交换)。</li>
 * </ul>
 * CRC-16/MODBUS 参考实现自证:标准校验向量 "123456789" → 0x4B37。
 */
class ModbusRtuRealTest {

    // ---- 夹具 ----

    @Data
    @Protocol(id = "real-modbus-reg")
    static class Reg16 {
        @ProtocolField(order = 1, size = 16)
        private int value;
    }

    @Data
    @Protocol(id = "real-modbus-req")
    static class ReadHoldingReq implements Checksum {
        @ProtocolField(order = 1, size = 8)
        private int addr = 0x11;
        @ProtocolField(order = 2, size = 8)
        private int func = 3;
        @ProtocolField(order = 3, size = 16)
        private int startAddr;
        @ProtocolField(order = 4, size = 16)
        private int qty;
        @ProtocolField(order = 5, size = 16, endian = Endian.LITTLE)
        @ChecksumField
        private int crc;

        @Override
        public long compute(String field, byte[] serialized) {
            return crc16Modbus(serialized, 0, serialized.length - 2);
        }
    }

    @Data
    @Protocol(id = "real-modbus-resp")
    static class ReadHoldingResp implements Checksum {
        @ProtocolField(order = 1, size = 8)
        private int addr = 1;
        @ProtocolField(order = 2, size = 8)
        private int func = 3;
        @ProtocolField(order = 3, size = 8)
        private int byteCount;
        @ProtocolField(order = 4, type = FieldType.LIST, countField = "byteCount",
                countUnit = com.netproto.annotation.CountUnit.BYTES, elementClass = Reg16.class)
        private List<Reg16> regs = new ArrayList<>();
        @ProtocolField(order = 5, size = 16, endian = Endian.LITTLE)
        @ChecksumField
        private int crc;

        @Override
        public long compute(String field, byte[] serialized) {
            return crc16Modbus(serialized, 0, serialized.length - 2);
        }
    }

    // ---- 测试 ----

    @Test
    void crc16ReferenceVector() {
        byte[] check = "123456789".getBytes();
        assertThat(crc16Modbus(check, 0, check.length)).isEqualTo(0x4B37);
    }

    /** 请求帧(经典):11 03 00 6B 00 03 76 87(CRC 低字节在前)。 */
    @Test
    void readHoldingRequestFrame() {
        ProtocolCodec<ReadHoldingReq> codec = new ProtocolCodec<>(ReadHoldingReq.class);
        ReadHoldingReq req = new ReadHoldingReq();
        req.setStartAddr(0x006B);
        req.setQty(3);
        byte[] wire = codec.serialize(req);
        assertThat(wire).containsExactly(
                0x11, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x76, 0x87);

        ReadHoldingReq back = codec.deserialize(wire);
        assertThat(back.getStartAddr()).isEqualTo(0x006B);
        assertThat(back.getQty()).isEqualTo(3);
        // CRC 校验通过:整帧重算一致
        assertThat(back.getCrc()).isEqualTo((int) crc16Modbus(wire, 0, 6));
    }

    /** 响应帧:byteCount=字节数(Modbus 特有口径)→ 2 个 u16 寄存器。 */
    @Test
    void readHoldingResponseFrame() {
        ProtocolCodec<ReadHoldingResp> codec = new ProtocolCodec<>(ReadHoldingResp.class);
        ReadHoldingResp resp = new ReadHoldingResp();
        Reg16 r1 = new Reg16();
        r1.setValue(0x0224);   // 548,典型温度×10
        Reg16 r2 = new Reg16();
        r2.setValue(0x0064);
        resp.setRegs(new ArrayList<>(List.of(r1, r2)));
        resp.setByteCount(4);

        byte[] wire = codec.serialize(resp);
        assertThat(wire).hasSize(9);
        assertThat(wire).containsSubsequence(0x01, 0x03, 0x04);   // addr/func/byteCount=4
        assertThat(crc16Modbus(wire, 0, 7)).isEqualTo(((wire[8] & 0xFF) << 8) | (wire[7] & 0xFF));

        ReadHoldingResp back = codec.deserialize(wire);
        assertThat(back.getRegs()).hasSize(2);
        assertThat(back.getRegs().get(0).getValue()).isEqualTo(0x0224);
        assertThat(back.getRegs().get(1).getValue()).isEqualTo(0x0064);
    }

    /** CRC-16/MODBUS:poly 0x8005(反射 0xA001),init 0xFFFF,RefIn/RefOut,XorOut 0。 */
    static long crc16Modbus(byte[] data, int off, int len) {
        int crc = 0xFFFF;
        for (int i = 0; i < len; i++) {
            crc ^= data[off + i] & 0xFF;
            for (int b = 0; b < 8; b++) {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xA001 : crc >> 1;
            }
        }
        return crc & 0xFFFF;
    }
}
