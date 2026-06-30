package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SentinelListTest {

    @Test
    void roundTripsSentinelList() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsNameSentinel> codec = new ProtocolCodec<>(DnsNameSentinel.class);

        DnsNameSentinel name = new DnsNameSentinel();
        name.getLabels().add(new DnsLabel("www"));
        name.getLabels().add(new DnsLabel("com"));

        byte[] out = codec.serialize(name);
        // www(03 77 77 77) + com(03 63 6f 6d) + 0x00 结束
        assertThat(out).containsExactly(
                0x03, 0x77, 0x77, 0x77,
                0x03, 0x63, 0x6f, 0x6d,
                0x00);

        DnsNameSentinel parsed = codec.deserialize(out);
        assertThat(parsed.getLabels()).hasSize(2);
        assertThat(parsed.getLabels().get(0).getContent()).containsExactly('w', 'w', 'w');
        assertThat(parsed.getLabels().get(1).getContent()).containsExactly('c', 'o', 'm');
    }

    @Test
    void roundTripsEmptySentinelList() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsNameSentinel> codec = new ProtocolCodec<>(DnsNameSentinel.class);

        DnsNameSentinel name = new DnsNameSentinel();  // 空 labels

        byte[] out = codec.serialize(name);
        assertThat(out).containsExactly(0x00);  // 直接以标记开始

        DnsNameSentinel parsed = codec.deserialize(out);
        assertThat(parsed.getLabels()).isEmpty();
    }
}
