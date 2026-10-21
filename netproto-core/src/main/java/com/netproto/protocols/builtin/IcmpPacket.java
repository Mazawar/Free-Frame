package com.netproto.protocols.builtin;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.ChecksumField;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.Checksum;
import lombok.Data;
import lombok.ToString;

import java.util.Arrays;

/**
 * ICMP(RFC 792):type/code/checksum 公共头 + 其余全部入 payload
 * (对 echo/不可达/超时等所有类型都稳健;echo 的 id/seq 在 payload 内)。
 * 校验和覆盖整个 ICMP 报文(头+payload)。
 */
@Data
@ToString
@Protocol(id = "icmp", name = "ICMP", builtin = true)
@BindOn(parent = "ipv4", when = "protocol == 1")
public class IcmpPacket implements Checksum {

    /** 类型:0=echo reply, 8=echo request, 3=不可达, 11=超时… */
    @ProtocolField(order = 1, size = 8, label = "Type")
    private int type;

    @ProtocolField(order = 2, size = 8, label = "Code")
    private int code;

    @ProtocolField(order = 3, size = 16, label = "Checksum")
    @ChecksumField
    private int checksum;

    @Payload
    private byte[] payload;

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"checksum".equals(field)) {
            return -1;
        }
        return Ipv4Packet.onesComplementSum(serialized);
    }
}
