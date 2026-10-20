package com.netproto.protocols.builtin;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * ICMPv6(RFC 4443,基本头):类型 + 代码 + 校验和,其余进 payload。
 * 校验和在 IPv6 下强制要求伪头(RFC 8200 §8.1,跨层信息),与 UDP/TCP 同一演示边界:
 * 解析原样展示,组装不计算(置 0)。
 */
@Data
@ToString
@Protocol(id = "icmpv6", name = "ICMPv6", builtin = true)
@BindOn(parent = "ipv6", when = "nextHeader == 58")
public class Icmpv6Packet {

    /** 128=Echo Request, 129=Echo Reply, 1=目的不可达, 3=超时…(其余报文体各异,进 payload) */
    @ProtocolField(order = 1, size = 8, label = "Type")
    private int type;

    @ProtocolField(order = 2, size = 8, label = "Code")
    private int code;

    @ProtocolField(order = 3, size = 16, label = "Checksum")
    private int checksum;

    @Payload
    private byte[] payload;
}
