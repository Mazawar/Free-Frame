package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Ipv4HeaderTest {

    @Test
    void roundTripsMinimalHeader() {
        new ProtocolCodec<>(Ipv4Header.class);
        ProtocolCodec<Ipv4Header> codec = new ProtocolCodec<>(Ipv4Header.class);

        Ipv4Header original = new Ipv4Header();
        original.setVersion(4);
        original.setIhl(5); // 无 options -> 20 字节
        original.setTos(0);
        original.setTotalLength(20);
        original.setIdentification(0x1234);
        original.setFlags(0);
        original.setFragmentOffset(0);
        original.setTtl(64);
        original.setProtocol(17); // UDP
        original.setHeaderChecksum(0xABCD);
        original.setSourceIp(0x0A000001);      // 10.0.0.1
        original.setDestinationIp(0x0A000002); // 10.0.0.2
        original.setOptions(new byte[0]);

        byte[] out = codec.serialize(original);
        assertThat(out).hasSize(20);
        assertThat(out[0]).isEqualTo((byte) 0x45); // version=4, ihl=5

        Ipv4Header parsed = codec.deserialize(out);
        assertThat(parsed.getVersion()).isEqualTo(4);
        assertThat(parsed.getIhl()).isEqualTo(5);
        assertThat(parsed.getTotalLength()).isEqualTo(20);
        assertThat(parsed.getTtl()).isEqualTo(64);
        assertThat(parsed.getProtocol()).isEqualTo(17);
        assertThat(parsed.getHeaderChecksum()).isEqualTo(0xABCD);
        assertThat(parsed.getSourceIp()).isEqualTo(0x0A000001);
        assertThat(parsed.getDestinationIp()).isEqualTo(0x0A000002);
    }

    @Test
    void roundTripsWithOptions() {
        new ProtocolCodec<>(Ipv4Header.class);
        ProtocolCodec<Ipv4Header> codec = new ProtocolCodec<>(Ipv4Header.class);

        Ipv4Header original = new Ipv4Header();
        original.setVersion(4);
        original.setIhl(6); // 1 个 option word = 4 字节 options -> 24 字节头
        original.setTos(0);
        original.setTotalLength(24);
        original.setIdentification(0);
        original.setFlags(0);
        original.setFragmentOffset(0);
        original.setTtl(64);
        original.setProtocol(17);
        original.setHeaderChecksum(0);
        original.setSourceIp(0x0A000001);
        original.setDestinationIp(0x0A000002);
        original.setOptions(new byte[]{0x01, 0x01, 0x00, 0x00}); // 4 字节 NOP option

        byte[] out = codec.serialize(original);
        assertThat(out).hasSize(24); // 20 + 4 options

        Ipv4Header parsed = codec.deserialize(out);
        assertThat(parsed.getIhl()).isEqualTo(6);
        assertThat(parsed.getOptions()).containsExactly(0x01, 0x01, 0x00, 0x00);
    }

    @Test
    void roundTripsNestedEthernetFrame() {
        new ProtocolCodec<>(Ipv4Header.class);
        new ProtocolCodec<>(EthernetFrame.class);
        ProtocolCodec<EthernetFrame> codec = new ProtocolCodec<>(EthernetFrame.class);

        EthernetFrame frame = new EthernetFrame();
        frame.setDstMac(0xAABBCCDDEEFFL);
        frame.setSrcMac(0x112233445566L);
        frame.setEtherType(0x0800); // IPv4
        Ipv4Header ip = new Ipv4Header();
        ip.setVersion(4);
        ip.setIhl(5);
        ip.setTos(0);
        ip.setTotalLength(20);
        ip.setIdentification(0);
        ip.setFlags(0);
        ip.setFragmentOffset(0);
        ip.setTtl(64);
        ip.setProtocol(17);
        ip.setHeaderChecksum(0);
        ip.setSourceIp(0x0A000001);
        ip.setDestinationIp(0x0A000002);
        ip.setOptions(new byte[0]);
        frame.setPayload(ip);

        byte[] out = codec.serialize(frame);
        assertThat(out).hasSize(14 + 20); // 以太网头14 + IP头20

        EthernetFrame parsed = codec.deserialize(out);
        assertThat(parsed.getDstMac()).isEqualTo(0xAABBCCDDEEFFL);
        assertThat(parsed.getEtherType()).isEqualTo(0x0800);
        assertThat(parsed.getPayload().getIhl()).isEqualTo(5);
        assertThat(parsed.getPayload().getTtl()).isEqualTo(64);
    }
}
