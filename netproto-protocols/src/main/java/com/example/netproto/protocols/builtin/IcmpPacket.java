package com.example.netproto.protocols.builtin;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.ChecksumField;
import com.example.netproto.annotation.Payload;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.Checksum;
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
    @ProtocolField(order = 1, size = 8)
    private int type;

    @ProtocolField(order = 2, size = 8)
    private int code;

    @ProtocolField(order = 3, size = 16)
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
