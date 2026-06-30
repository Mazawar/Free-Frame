package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * 最简以太网帧:目的 MAC(6) + 源 MAC(6) + EtherType(2) + IP 头(嵌套)。
 * 仅用于验证 NESTED 嵌套 round-trip,非完整以太网(无 VLAN/帧尾)。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class EthernetFrame {

    @ProtocolField(order = 1, size = 48) private long dstMac;     // 6 字节当 long
    @ProtocolField(order = 2, size = 48) private long srcMac;
    @ProtocolField(order = 3, size = 16) private int etherType;
    @ProtocolField(order = 4, type = FieldType.NESTED) private Ipv4Header payload;
}
