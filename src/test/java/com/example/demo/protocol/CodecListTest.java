package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CodecListTest {

    @Test
    void roundTripsCountDrivenList() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsQuestion> codec = new ProtocolCodec<>(DnsQuestion.class);

        DnsQuestion q = new DnsQuestion();
        q.setLabelCount(3);
        q.getLabels().add(new DnsLabel("www"));      // 03 77 77 77
        q.getLabels().add(new DnsLabel("example"));  // 07 65 78 61 6d 70 6c 65
        q.getLabels().add(new DnsLabel("com"));      // 03 63 6f 6d

        byte[] out = codec.serialize(q);
        assertThat(out).containsExactly(
                0x03,
                0x03, 0x77, 0x77, 0x77,
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                0x03, 0x63, 0x6f, 0x6d);

        DnsQuestion parsed = codec.deserialize(out);
        assertThat(parsed.getLabelCount()).isEqualTo(3);
        assertThat(parsed.getLabels()).hasSize(3);
        assertThat(parsed.getLabels().get(0).getContent()).containsExactly('w', 'w', 'w');
        assertThat(parsed.getLabels().get(1).getContent()).containsExactly('e', 'x', 'a', 'm', 'p', 'l', 'e');
        assertThat(parsed.getLabels().get(2).getContent()).containsExactly('c', 'o', 'm');
    }

    @Test
    void rejectsCountSizeMismatchOnSerialize() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsQuestion> codec = new ProtocolCodec<>(DnsQuestion.class);

        DnsQuestion q = new DnsQuestion();
        q.setLabelCount(3);
        q.getLabels().add(new DnsLabel("a"));

        assertThatThrownBy(() -> codec.serialize(q))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("countField");
    }

    @Test
    void handlesZeroCountList() {
        new ProtocolCodec<>(DnsLabel.class);
        ProtocolCodec<DnsQuestion> codec = new ProtocolCodec<>(DnsQuestion.class);

        DnsQuestion q = new DnsQuestion();
        q.setLabelCount(0);

        byte[] out = codec.serialize(q);
        assertThat(out).containsExactly(0x00);

        DnsQuestion parsed = codec.deserialize(out);
        assertThat(parsed.getLabelCount()).isEqualTo(0);
        assertThat(parsed.getLabels()).isEmpty();
    }
}
