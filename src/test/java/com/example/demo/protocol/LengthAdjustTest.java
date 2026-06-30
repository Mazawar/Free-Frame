package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LengthAdjustTest {

    @Test
    void roundTripsWithLengthAdjust() {
        ProtocolCodec<IpFragment> codec = new ProtocolCodec<>(IpFragment.class);

        IpFragment f = new IpFragment();
        f.setTotalLen(24);   // payload 应占 24 - 20 = 4 字节
        f.setPayload(new byte[]{0x01, 0x02, 0x03, 0x04});

        byte[] out = codec.serialize(f);
        // 2字节 totalLen + 4字节 payload = 6字节
        assertThat(out).containsExactly(0x00, 0x18, 0x01, 0x02, 0x03, 0x04);  // 24 = 0x0018

        IpFragment parsed = codec.deserialize(out);
        assertThat(parsed.getTotalLen()).isEqualTo(24);
        assertThat(parsed.getPayload()).containsExactly(0x01, 0x02, 0x03, 0x04);
    }

    @Test
    void roundTripsEmptyPayloadWhenLengthMatchesHeader() {
        // totalLen = 20,adjust=-20 → payload = 0 字节(边界情况)
        ProtocolCodec<IpFragment> codec = new ProtocolCodec<>(IpFragment.class);

        IpFragment f = new IpFragment();
        f.setTotalLen(20);  // 20 - 20 = 0 字节 payload
        f.setPayload(new byte[0]);

        byte[] out = codec.serialize(f);
        assertThat(out).containsExactly(0x00, 0x14);  // 仅 totalLen(20=0x14),无 payload
    }
}
