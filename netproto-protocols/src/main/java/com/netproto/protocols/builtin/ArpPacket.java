package com.netproto.protocols.builtin;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * ARP 报文(RFC 826,以太网 + IPv4 场景):固定 28 字节,无 payload(叶子协议)。
 */
@Data
@ToString
@Protocol(id = "arp", name = "ARP", builtin = true)
@BindOn(parent = "ethernet", when = "etherType == 0x0806")
public class ArpPacket {

    /** 硬件类型:1 = 以太网。 */
    @ProtocolField(order = 1, size = 16)
    private int hardwareType = 1;

    /** 协议类型:0x0800 = IPv4。 */
    @ProtocolField(order = 2, size = 16)
    private int protocolType = 0x0800;

    @ProtocolField(order = 3, size = 8)
    private int hardwareAddrLen = 6;

    @ProtocolField(order = 4, size = 8)
    private int protocolAddrLen = 4;

    /** 操作:1 = request,2 = reply。 */
    @ProtocolField(order = 5, size = 16)
    private int operation;

    @ProtocolField(order = 6, size = 48)
    private long senderMac;

    @ProtocolField(order = 7, size = 32)
    private int senderIp;

    @ProtocolField(order = 8, size = 48)
    private long targetMac;

    @ProtocolField(order = 9, size = 32)
    private int targetIp;
}
