package com.netproto.protocols.builtin;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import com.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * IPv6 基本头(RFC 8200,固定 40 字节,无扩展头)。
 * <ul>
 *   <li>payloadLength 组装期自动 = 内层字节数;</li>
 *   <li>nextHeader 由 StackEncoder 按子协议绑定的 when 自动接线(udp=17/tcp=6/icmpv6=58);</li>
 *   <li>扩展头链(Hop-by-Hop/路由/分片…)不在分派树内:nextHeader 为扩展头类型时解析停在本层
 *       (诚实边界,与「只解析被标记的协议」同一设计取舍)。</li>
 * </ul>
 */
@Data
@ToString
@Protocol(id = "ipv6", name = "IPv6", builtin = true)
@BindOn(parent = "ethernet", when = "etherType == 0x86DD")
@BindOn(parent = "vlan", when = "innerEtherType == 0x86DD")
public class Ipv6Packet implements PayloadAware {

    @ProtocolField(order = 1, size = 4, label = "Version")
    private int version = 6;

    @ProtocolField(order = 2, size = 8, label = "Traffic Class")
    private int trafficClass;

    @ProtocolField(order = 3, size = 20, label = "Flow Label")
    private int flowLabel;

    @ProtocolField(order = 4, size = 16, label = "Payload Length")
    private int payloadLength;

    @ProtocolField(order = 5, size = 8, label = "Next Header")
    private int nextHeader;

    @ProtocolField(order = 6, size = 8, label = "Hop Limit")
    private int hopLimit = 64;

    @ProtocolField(order = 7, size = 128, type = FieldType.BYTES, label = "Source")
    private byte[] srcIp6 = new byte[16];

    @ProtocolField(order = 8, size = 128, type = FieldType.BYTES, label = "Destination")
    private byte[] dstIp6 = new byte[16];

    @Payload
    private byte[] payload;

    @Override
    public void onPayload(byte[] innerPayload) {
        this.version = 6;
        this.payloadLength = innerPayload.length;
    }
}
