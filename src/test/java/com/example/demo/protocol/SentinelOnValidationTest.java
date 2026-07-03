package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SentinelOnValidationTest {

    @Data
    @ProtocolPacket(port = 0)
    public static class BothSentinelOnAndCount {
        @ProtocolField(order = 1, size = 8) private int n;
        @ProtocolField(order = 2, type = FieldType.LIST,
                countField = "n", elementClass = DnsLabel.class,
                sentinelOn = "length", sentinelValue = 0)
        private List<DnsLabel> labels;
    }

    @Test
    void rejectsSentinelOnWithCountField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BothSentinelOnAndCount.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sentinelOn");
    }

    @Data
    @ProtocolPacket(port = 0)
    public static class UnknownSentinelOnField {
        @ProtocolField(order = 1, type = FieldType.LIST,
                elementClass = DnsLabel.class,
                sentinelOn = "ghost", sentinelValue = 0)
        private List<DnsLabel> labels;
    }

    @Test
    void rejectsUnknownSentinelOnField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(UnknownSentinelOnField.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ghost");
    }
}
