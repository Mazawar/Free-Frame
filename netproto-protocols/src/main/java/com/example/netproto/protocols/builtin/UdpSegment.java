package com.example.netproto.protocols.builtin;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Payload;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * UDP 段(RFC 768)。
 * length 组装期自动 = 8 + payload 长度;checksum 置 0 —— UDP 校验和需要
 * 父层 IP 构成伪头,跨层信息注解层不取(0 在 IPv4 UDP 里合法 = 未计算,见设计文档边界)。
 */
@Data
@ToString
@Protocol(id = "udp", name = "UDP", builtin = true)
@BindOn(parent = "ipv4", when = "protocol == 17")
public class UdpSegment implements PayloadAware {

    @ProtocolField(order = 1, size = 16)
    private int srcPort;

    @ProtocolField(order = 2, size = 16)
    private int dstPort;

    /** 长度(含 8 字节 UDP 头)。 */
    @ProtocolField(order = 3, size = 16)
    private int length;

    /** 0 = 未计算(IPv4 下合法;伪头校验和属跨层,见设计文档)。 */
    @ProtocolField(order = 4, size = 16)
    private int checksum;

    @Payload
    private byte[] payload;

    @Override
    public void onPayload(byte[] innerPayload) {
        this.length = 8 + innerPayload.length;
        this.checksum = 0;
    }
}
