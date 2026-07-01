package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class TcpChecksumParityTest {

    @Test
    void ourTcpChecksumMatchesPcap4j() throws Exception {
        java.net.Inet4Address src = (java.net.Inet4Address) InetAddress.getByName("10.0.0.1");
        java.net.Inet4Address dst = (java.net.Inet4Address) InetAddress.getByName("10.0.0.2");

        TcpPacket.Builder tcpB = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) 12345))
                .dstPort(TcpPort.getInstance((short) 80))
                .sequenceNumber(1000)
                .acknowledgmentNumber(0)
                .dataOffset((byte) 5)
                .reserved((byte) 0)
                .psh(false).ack(false).urg(false).rst(false).syn(true).fin(false)
                .window((short) 8192)
                .urgentPointer((short) 0)
                .correctLengthAtBuild(true)
                .correctChecksumAtBuild(true)
                .srcAddr(src)
                .dstAddr(dst);
        IpV4Packet.Builder ipB = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr(src)
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(tcpB);
        IpV4Packet ipPkt = ipB.build();
        TcpPacket tcpPkt = (TcpPacket) ipPkt.getPayload();

        short pcapChecksum = tcpPkt.getHeader().getChecksum();
        byte[] pcapTcpBytes = tcpPkt.getRawData();

        ProtocolCodec<TcpSegmentWithChecksum> codec = new ProtocolCodec<>(TcpSegmentWithChecksum.class);
        TcpSegmentWithChecksum ours = new TcpSegmentWithChecksum();
        ours.setSrcPort(12345);
        ours.setDstPort(80);
        ours.setSeqNumber(1000);
        ours.setAckNumber(0);
        ours.setDataOffset(5);
        ours.setReserved(0);
        ours.setFlags(0x02);   // SYN
        ours.setWindow(8192);
        ours.setUrgentPointer(0);
        ours.setChecksum(0);
        ours.setPseudoSourceIp(0x0A000001);
        ours.setPseudoDestIp(0x0A000002);
        ours.setPseudoProtocol(6);
        byte[] ourBytes = codec.serialize(ours);

        int ourChecksum = ((ourBytes[16] & 0xFF) << 8) | (ourBytes[17] & 0xFF);
        assertThat(ourChecksum).isEqualTo(pcapChecksum & 0xFFFF);
        assertThat(ourBytes).containsExactly(pcapTcpBytes);
    }
}
