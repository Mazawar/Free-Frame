package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class EnumParityTest {

    @Test
    void ourEnumProtocolMatchesPcap4j() throws Exception {
        // pcap4j 构造 IP 包(protocol=UDP)
        IpV4Packet pcapPkt = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)   // = 17
                .srcAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.1"))
                .dstAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.2"))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .build();

        // protocol 字节在 IP 头第 10 字节(offset 9)
        byte protocolByte = pcapPkt.getHeader().getRawData()[9];

        ProtocolCodec<Ipv4HeaderWithEnum> codec = new ProtocolCodec<>(Ipv4HeaderWithEnum.class);
        Ipv4HeaderWithEnum ours = codec.deserialize(new byte[]{protocolByte});

        // parity:我们的 enum 值 == pcap4j 的 protocol(都 UDP/17)
        assertThat(ours.getProtocol()).isEqualTo(IpProtocol.UDP);
        assertThat(ours.getProtocol().value()).isEqualTo(pcapPkt.getHeader().getProtocol().value() & 0xFF);
    }
}
