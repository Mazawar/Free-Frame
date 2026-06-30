package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class Ipv4ChecksumParityTest {

    @Test
    void ourChecksumMatchesPcap4j() throws Exception {
        // pcap4j 构造 IP 包(correctChecksumAtBuild=true,自动算校验和)
        IpV4Packet pcapPkt = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .totalLength((short) 20)
                .identification((short) 0)
                .reservedFlag(false)
                .dontFragmentFlag(false)
                .moreFragmentFlag(false)
                .fragmentOffset((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.1"))
                .dstAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.2"))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .build();

        short pcapChecksum = pcapPkt.getHeader().getHeaderChecksum();
        byte[] pcapHeaderBytes = pcapPkt.getHeader().getRawData();

        // 我们的 codec 序列化同样的字段
        ProtocolCodec<Ipv4HeaderWithChecksum> codec = new ProtocolCodec<>(Ipv4HeaderWithChecksum.class);
        Ipv4HeaderWithChecksum ours = new Ipv4HeaderWithChecksum();
        ours.setVersion(4);
        ours.setIhl(5);
        ours.setTos(0);
        ours.setTotalLength(20);
        ours.setIdentification(0);
        ours.setFlags(0);   // pcap4j: all flags false
        ours.setFragmentOffset(0);
        ours.setTtl(64);
        ours.setProtocol(17);   // UDP
        ours.setHeaderChecksum(0);  // 引擎会算
        ours.setSourceIp(0x0A000001);      // 10.0.0.1
        ours.setDestinationIp(0x0A000002); // 10.0.0.2
        byte[] ourBytes = codec.serialize(ours);

        // parity:我们的校验和字段(offset 10-11)== pcap4j 的校验和
        int ourChecksum = ((ourBytes[10] & 0xFF) << 8) | (ourBytes[11] & 0xFF);
        assertThat(ourChecksum).isEqualTo(pcapChecksum & 0xFFFF);

        // 额外:除校验和外,整个头字节应一致(我们的字节 10-11 是算出来的,应等于 pcap4j 的)
        assertThat(ourBytes).containsExactly(pcapHeaderBytes);
    }
}
