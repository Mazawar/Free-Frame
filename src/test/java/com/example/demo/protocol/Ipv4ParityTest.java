package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class Ipv4ParityTest {

    @Test
    void ourCodecMatchesPcap4jFieldByField() throws Exception {
        // 1. 用 pcap4j 构造一个标准 IPv4 包(独立裁判)
        IpV4Packet pcapPkt = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0x1234)
                .reservedFlag(false)
                .dontFragmentFlag(true)
                .moreFragmentFlag(false)
                .fragmentOffset((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.1"))
                .dstAddr((java.net.Inet4Address) InetAddress.getByName("10.0.0.2"))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .build();

        byte[] headerBytes = pcapPkt.getHeader().getRawData(); // pcap4j 真实头字节(20 字节)

        // 2. 喂给我们的 codec
        new ProtocolCodec<>(Ipv4Header.class);
        ProtocolCodec<Ipv4Header> codec = new ProtocolCodec<>(Ipv4Header.class);
        Ipv4Header ours = codec.deserialize(headerBytes);

        // 3. 逐字段对比(parity)
        org.pcap4j.packet.IpV4Packet.IpV4Header pcapHeader = pcapPkt.getHeader();

        assertThat(ours.getVersion()).isEqualTo(pcapHeader.getVersion().value() & 0xFF);
        assertThat(ours.getIhl()).isEqualTo(pcapHeader.getIhlAsInt());
        assertThat(ours.getTos()).isEqualTo(pcapHeader.getTos().value() & 0xFF);
        assertThat(ours.getTotalLength()).isEqualTo(pcapHeader.getTotalLengthAsInt());
        assertThat(ours.getIdentification()).isEqualTo(pcapHeader.getIdentificationAsInt());
        // flags: 我们的 3-bit = reserved<<2 | df<<1 | mf
        int expectedFlags = (pcapHeader.getReservedFlag() ? 4 : 0)
                | (pcapHeader.getDontFragmentFlag() ? 2 : 0)
                | (pcapHeader.getMoreFragmentFlag() ? 1 : 0);
        assertThat(ours.getFlags()).isEqualTo(expectedFlags);
        assertThat(ours.getFragmentOffset()).isEqualTo(pcapHeader.getFragmentOffset() & 0xFFFF);
        assertThat(ours.getTtl()).isEqualTo(pcapHeader.getTtlAsInt());
        assertThat(ours.getProtocol()).isEqualTo(pcapHeader.getProtocol().value() & 0xFF);
        assertThat(ours.getHeaderChecksum()).isEqualTo(pcapHeader.getHeaderChecksum() & 0xFFFF);

        // IP 地址:pcap4j 用 Inet4Address,我们用 int
        assertThat(ours.getSourceIp())
                .isEqualTo(ipToInt((java.net.Inet4Address) pcapHeader.getSrcAddr()));
        assertThat(ours.getDestinationIp())
                .isEqualTo(ipToInt((java.net.Inet4Address) pcapHeader.getDstAddr()));

        // options 为空(ihl=5)
        assertThat(ours.getOptions()).isEmpty();
    }

    private static int ipToInt(java.net.Inet4Address addr) {
        byte[] b = addr.getAddress();
        return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
    }
}
