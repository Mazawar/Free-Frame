package com.example.demo.protocol.realworld.s7;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * S7 协议头(西门子 S7comm,真·私有工业协议):protocolId 0x32 + msgType 分派,10 字节。
 * <pre>
 *  | 0x32 | msgType(8b) | reserved(16b) | pduRef(16b) | paramLen(16b) | dataLen(16b) |
 *    msgType: 1=Job(请求) 2=Ack 3=Ack-Data(响应)
 * </pre>
 * 验证点:三级头穿透分派(tcp→tpkt→cotp→s7→job);paramLen 由 onPayload 回填。
 */
@Data
@ToString
@Protocol(id = "s7", name = "S7comm", group = "S7comm")
@BindOn(parent = "cotp", when = "pduType == 0xF0")
public class S7Header implements PayloadAware {

    @ProtocolField(order = 1, size = 8)
    private int protocolId = 0x32;

    /** 1=Job 3=Ack-Data:子协议分派字段。 */
    @ProtocolField(order = 2, size = 8)
    private int msgType;

    @ProtocolField(order = 3, size = 16)
    private int reserved;

    @ProtocolField(order = 4, size = 16)
    private int pduRef;

    /** 参数区长度,组装期自动。 */
    @ProtocolField(order = 5, size = 16)
    private int paramLength;

    /** 数据区长度(读请求子集无数据区 = 0)。 */
    @ProtocolField(order = 6, size = 16)
    private int dataLength;

    @Override
    public void onPayload(byte[] inner) {
        this.paramLength = inner.length;
        this.dataLength = 0;
    }
}
