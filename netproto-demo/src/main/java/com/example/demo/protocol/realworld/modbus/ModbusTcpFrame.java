package com.example.demo.protocol.realworld.modbus;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import com.example.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * Modbus TCP(MBAP + PDU,工业事实标准,TCP 502)。
 * <pre>
 *  | transactionId(16b) | protocolId(16b)=0 | length(16b) | unitId(8b) | functionCode(8b) | data... |
 *    length = unitId + functionCode + data(即 MBAP 头 6 字节之后的全部)
 * </pre>
 * 验证点:公共头 + functionCode 字段分派;length 由 onPayload 钩子组装期自动回填。
 */
@Data
@ToString
@Protocol(id = "modbus", name = "Modbus TCP")
@BindOn(parent = "tcp", when = "dstPort == 502 || srcPort == 502")
public class ModbusTcpFrame implements PayloadAware {

    @ProtocolField(order = 1, size = 16, type = FieldType.UNSIGNED)
    private int transactionId;

    /** 0 = Modbus 协议。 */
    @ProtocolField(order = 2, size = 16)
    private int protocolId;

    /** 后续长度 = unitId + PDU,组装期自动。 */
    @ProtocolField(order = 3, size = 16)
    private int length;

    @ProtocolField(order = 4, size = 8)
    private int unitId;

    /** 功能码:子协议分派字段(3=读保持寄存器响应 16=写多寄存器请求)。 */
    @ProtocolField(order = 5, size = 8)
    private int functionCode;

    @Override
    public void onPayload(byte[] inner) {
        this.length = 2 + inner.length;   // unitId + functionCode + data
    }
}
