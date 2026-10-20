package com.netproto.protocols.builtin;

import com.netproto.stack.DecodedPacket;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackDecoder;
import com.netproto.stack.StackEncoder;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * IPv6 栈:pcap4j parity、双栈分派(ethernet▸ipv6▸udp/tcp/icmpv6)、VLAN 分派、
 * 未知 nextHeader(扩展头)停在本层 —— 引擎「只解析被标记的协议」边界在 IPv6 下的表现。
 */
class Ipv6StackTest {

    private static ProtocolRegistry registry() {
        return ProtocolRegistry.create(Arrays.asList(
                EthernetFrame.class, ArpPacket.class, Ipv4Packet.class, Ipv6Packet.class,
                IcmpPacket.class, Icmpv6Packet.class, UdpSegment.class, TcpSegment.class,
                VlanFrame.class));
    }

    @Test
    void ourCodecMatchesPcap4jFieldByField() throws Exception {
        IpV6Packet pcapPkt = new IpV6Packet.Builder()
                .version(IpVersion.IPV6)
                .trafficClass(org.pcap4j.packet.IpV6SimpleTrafficClass.newInstance((byte) 0xE0))
                .flowLabel(org.pcap4j.packet.IpV6SimpleFlowLabel.newInstance(0x5F1EA))
                .nextHeader(IpNumber.UDP)
                .hopLimit((byte) 64)
                .srcAddr((java.net.Inet6Address) InetAddress.getByName("2001:db8::1"))
                .dstAddr((java.net.Inet6Address) InetAddress.getByName("2001:db8::2"))
                .correctLengthAtBuild(true)
                .build();
        byte[] header = pcapPkt.getHeader().getRawData();   // 40 字节
        Ipv6Packet ours = new com.netproto.core.ProtocolCodec<>(Ipv6Packet.class).deserialize(header);

        IpV6Packet.IpV6Header pcapHeader = pcapPkt.getHeader();
        assertThat(ours.getVersion()).isEqualTo(pcapHeader.getVersion().value() & 0xFF);
        assertThat(ours.getTrafficClass()).isEqualTo(pcapHeader.getTrafficClass().value() & 0xFF);
        assertThat(ours.getFlowLabel()).isEqualTo(pcapHeader.getFlowLabel().value());
        assertThat(ours.getPayloadLength()).isEqualTo(pcapHeader.getPayloadLengthAsInt());
        assertThat(ours.getNextHeader()).isEqualTo(pcapHeader.getNextHeader().value() & 0xFF);
        assertThat(ours.getHopLimit()).isEqualTo(pcapHeader.getHopLimit() & 0xFF);
        assertThat(ours.getSrcIp6()).isEqualTo(pcapHeader.getSrcAddr().getAddress());
        assertThat(ours.getDstIp6()).isEqualTo(pcapHeader.getDstAddr().getAddress());
    }

    @Test
    void udpOverIpv6DispatchAndRoundTrip() {
        ProtocolRegistry r = registry();
        StackEncoder encoder = new StackEncoder(r);

        EthernetFrame eth = new EthernetFrame();
        Ipv6Packet ip = new Ipv6Packet();
        UdpSegment udp = new UdpSegment();
        udp.setSrcPort(52118);
        udp.setDstPort(1883);
        udp.setPayload(new byte[]{1, 2, 3});
        byte[] frame = encoder.encode(List.of(eth, ip, udp));

        // ethernet.etherType=0x86DD 与 ipv6.nextHeader=17 均为自动接线
        assertThat(frame[12]).isEqualTo((byte) 0x86);
        assertThat(frame[13]).isEqualTo((byte) 0xDD);
        assertThat(frame[20]).isEqualTo((byte) 17);

        DecodedPacket out = new StackDecoder(r, "ethernet").decode(frame, "t", 0, 1);
        assertThat(out.protocolPath()).isEqualTo("ethernet▸ipv6▸udp");
        assertThat(out.layers().get(1).packet()).isInstanceOf(Ipv6Packet.class);
        assertThat(((Ipv6Packet) out.layers().get(1).packet()).getNextHeader()).isEqualTo(17);
        assertThat(out.layers().get(2).packet()).isInstanceOf(UdpSegment.class);
    }

    @Test
    void tcpOverIpv6Dispatch() {
        ProtocolRegistry r = registry();
        StackEncoder encoder = new StackEncoder(r);
        TcpSegment tcp = new TcpSegment();
        tcp.setDstPort(443);
        tcp.setPayload(new byte[]{9});
        byte[] frame = encoder.encode(List.of(new EthernetFrame(), new Ipv6Packet(), tcp));
        assertThat(frame[20]).isEqualTo((byte) 6);
        assertThat(new StackDecoder(r, "ethernet").decode(frame, "t", 0, 1).protocolPath())
                .isEqualTo("ethernet▸ipv6▸tcp");
    }

    @Test
    void icmpv6Dispatch() {
        ProtocolRegistry r = registry();
        StackEncoder encoder = new StackEncoder(r);
        Icmpv6Packet icmp6 = new Icmpv6Packet();
        icmp6.setType(128);   // Echo Request
        icmp6.setPayload(new byte[]{0, 1, 2, 3});
        byte[] frame = encoder.encode(List.of(new EthernetFrame(), new Ipv6Packet(), icmp6));
        assertThat(frame[20]).isEqualTo((byte) 58);
        assertThat(new StackDecoder(r, "ethernet").decode(frame, "t", 0, 1).protocolPath())
                .isEqualTo("ethernet▸ipv6▸icmpv6");
    }

    @Test
    void unknownNextHeaderStopsAtIpv6() {
        ProtocolRegistry r = registry();
        StackEncoder encoder = new StackEncoder(r);
        Ipv6Packet ip = new Ipv6Packet();
        ip.setNextHeader(0);   // 0 = Hop-by-Hop 扩展头:分派树不下降
        ip.setPayload(new byte[]{0, 0, 1, 4});
        byte[] frame = encoder.encode(List.of(new EthernetFrame(), ip));
        assertThat(new StackDecoder(r, "ethernet").decode(frame, "t", 0, 1).protocolPath())
                .isEqualTo("ethernet▸ipv6");
    }

    @Test
    void ipv4OverVlanDispatch() {
        ProtocolRegistry r = registry();
        StackEncoder encoder = new StackEncoder(r);
        EthernetFrame eth = new EthernetFrame();
        VlanFrame vlan = new VlanFrame();
        vlan.setVlanId(42);
        UdpSegment udp = new UdpSegment();
        udp.setPayload(new byte[]{7});
        byte[] frame = encoder.encode(List.of(eth, vlan, new Ipv4Packet(), udp));

        assertThat(frame[12]).isEqualTo((byte) 0x81);   // etherType 0x8100 自动
        assertThat(frame[13]).isEqualTo((byte) 0x00);
        int tci = ((frame[14] & 0xFF) << 8) | (frame[15] & 0xFF);
        assertThat(tci & 0xFFF).isEqualTo(42);
        assertThat(frame[16]).isEqualTo((byte) 0x08);   // innerEtherType 0x0800 自动
        assertThat(frame[17]).isEqualTo((byte) 0x00);

        DecodedPacket out = new StackDecoder(r, "ethernet").decode(frame, "t", 0, 1);
        assertThat(out.protocolPath()).isEqualTo("ethernet▸vlan▸ipv4▸udp");
        assertThat(((VlanFrame) out.layers().get(1).packet()).getVlanId()).isEqualTo(42);
    }
}
