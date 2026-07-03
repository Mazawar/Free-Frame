package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DnsNameSentinelEdgeTest {

    @Test
    void emptyDnsNameRoundTrips() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsName> codec = new ProtocolCodec<>(DnsName.class);

        // 仅 0x00 → 空 labels
        DnsName parsed = codec.deserialize(new byte[]{0x00});
        assertThat(parsed.getLabels()).isEmpty();

        // 空序列化 → 仅 0x00
        byte[] out = codec.serialize(new DnsName());
        assertThat(out).containsExactly(0x00);
    }

    @Test
    void noSentinelReadsToEnd() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsName> codec = new ProtocolCodec<>(DnsName.class);

        // 一个 label,无 0x00(读到末尾)
        DnsName parsed = codec.deserialize(new byte[]{0x03, 0x63, 0x6f, 0x6d});
        assertThat(parsed.getLabels()).hasSize(1);
        assertThat(parsed.getLabels().get(0).getContent()).containsExactly('c', 'o', 'm');
    }
}
