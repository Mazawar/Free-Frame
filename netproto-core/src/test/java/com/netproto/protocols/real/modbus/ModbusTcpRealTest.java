package com.netproto.protocols.real.modbus;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Modbus TCP 真实帧测试(MBAP 头)。
 * <p>
 * MBAP:TransactionId(2B) + ProtocolId(2B)=0 + Length(2B)=其后全部字节数
 * (=UnitId 1B + PDU)。经典帧:读保持寄存器
 * {@code 00 01 00 00 00 06 01 03 00 6B 00 03}(Length=6,不含 MBAP 前 6 字节)。
 */
class ModbusTcpRealTest {

    @Data
    @Protocol(id = "real-modbus-tcp")
    static class MbapReadReq {
        @ProtocolField(order = 1, size = 16)
        private int transactionId;
        @ProtocolField(order = 2, size = 16)
        private int protocolId;
        /** = 其后字节数(unitId+func+start+qty = 6)。 */
        @ProtocolField(order = 3, size = 16)
        private int length = 6;
        @ProtocolField(order = 4, size = 8)
        private int unitId = 1;
        @ProtocolField(order = 5, size = 8)
        private int func = 3;
        @ProtocolField(order = 6, size = 16)
        private int startAddr;
        @ProtocolField(order = 7, size = 16)
        private int qty;
    }

    @Test
    void classicReadHoldingFrame() {
        ProtocolCodec<MbapReadReq> codec = new ProtocolCodec<>(MbapReadReq.class);
        MbapReadReq req = new MbapReadReq();
        req.setTransactionId(1);
        req.setStartAddr(0x006B);
        req.setQty(3);

        byte[] wire = codec.serialize(req);
        assertThat(wire).containsExactly(
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                0x01, 0x03, 0x00, 0x6B, 0x00, 0x03);

        MbapReadReq back = codec.deserialize(wire);
        assertThat(back.getTransactionId()).isEqualTo(1);
        assertThat(back.getLength()).isEqualTo(6);
        assertThat(back.getStartAddr()).isEqualTo(0x006B);
    }
}
