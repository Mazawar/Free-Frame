package com.netproto.protocols.ip;

import com.netproto.annotation.ProtocolField;
import com.netproto.annotation.Protocol;
import com.netproto.core.ProtocolEnum;
import lombok.Data;
import lombok.ToString;

/**
 * IPv4 头的 protocol 字段用枚举表达(而非裸 int)。
 * 仅含 protocol 字段用于 parity 验收(对比 pcap4j 的 getProtocol())。
 * 字段声明为 ProtocolEnum 接口类型 + enumClass 指定具体枚举(支持未知值兜底)。
 */
@Data
@ToString
@Protocol(id = "ipv4-header-enum")
public class Ipv4HeaderWithEnum {

    @ProtocolField(order = 1, size = 8, enumClass = IpProtocol.class)
    private ProtocolEnum protocol;
}
