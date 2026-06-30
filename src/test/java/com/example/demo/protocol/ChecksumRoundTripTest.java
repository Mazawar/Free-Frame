package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ChecksumRoundTripTest {

    @Test
    void checksumSurvivesRoundTrip() {
        ProtocolCodec<Ipv4HeaderWithChecksum> codec = new ProtocolCodec<>(Ipv4HeaderWithChecksum.class);

        Ipv4HeaderWithChecksum h = new Ipv4HeaderWithChecksum();
        h.setVersion(4);
        h.setIhl(5);
        h.setTotalLength(20);
        h.setTtl(64);
        h.setProtocol(17);
        h.setSourceIp(0x0A000001);
        h.setDestinationIp(0x0A000002);
        h.setHeaderChecksum(0);  // 引擎算

        byte[] out = codec.serialize(h);
        // 反序列化:校验和字段照常读出(不验证)
        Ipv4HeaderWithChecksum parsed = codec.deserialize(out);
        assertThat(parsed.getVersion()).isEqualTo(4);
        assertThat(parsed.getHeaderChecksum()).isNotZero();  // 引擎算出了值

        // 再序列化:校验和应稳定(同样的字段 → 同样的校验和)
        byte[] out2 = codec.serialize(parsed);
        assertThat(out2).containsExactly(out);
    }
}
