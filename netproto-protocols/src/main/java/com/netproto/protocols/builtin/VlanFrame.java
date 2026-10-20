package com.netproto.protocols.builtin;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 802.1Q VLAN 标签(IEEE 802.1Q,etherType 0x8100):TCI(优先级 3 + DEI 1 + VLAN ID 12)
 * + 内层 etherType。ipv4/ipv6/arp 同时挂在 vlan 下按 innerEtherType 分派,与挂在
 * ethernet 下同一机制(VMware/Hyper-V 虚拟交换机的真实流量常带此标签)。
 */
@Data
@ToString
@Protocol(id = "vlan", name = "802.1Q Virtual LAN", builtin = true)
@BindOn(parent = "ethernet", when = "etherType == 0x8100")
public class VlanFrame {

    /** 优先级(802.1p,0-7)。 */
    @ProtocolField(order = 1, size = 3, group = "TCI", label = "Priority")
    private int priority;

    /** Drop Eligible Indicator。 */
    @ProtocolField(order = 2, size = 1, group = "TCI", label = "DEI")
    private int dei;

    /** VLAN 标识(0=优先级标签, 0xFFF=保留)。 */
    @ProtocolField(order = 3, size = 12, group = "TCI", label = "VLAN ID")
    private int vlanId;

    @ProtocolField(order = 4, size = 16, label = "Inner EtherType")
    private int innerEtherType;

    @Payload
    private byte[] payload;
}
