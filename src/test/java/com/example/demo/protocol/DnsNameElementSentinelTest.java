package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DnsNameElementSentinelTest {

    @Test
    void roundTripsRealDnsName() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsName> codec = new ProtocolCodec<>(DnsName.class);

        DnsName name = new DnsName();
        name.getLabels().add(new DnsLabel("www"));
        name.getLabels().add(new DnsLabel("example"));
        name.getLabels().add(new DnsLabel("com"));

        byte[] out = codec.serialize(name);
        assertThat(out).containsExactly(
                0x03, 0x77, 0x77, 0x77,
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                0x03, 0x63, 0x6f, 0x6d,
                0x00);

        DnsName parsed = codec.deserialize(out);
        assertThat(parsed.getLabels()).hasSize(3);
        assertThat(parsed.getLabels().get(0).getContent()).containsExactly('w', 'w', 'w');
        assertThat(parsed.getLabels().get(1).getContent()).containsExactly('e', 'x', 'a', 'm', 'p', 'l', 'e');
        assertThat(parsed.getLabels().get(2).getContent()).containsExactly('c', 'o', 'm');
    }
}
