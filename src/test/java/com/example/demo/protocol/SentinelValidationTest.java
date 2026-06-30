package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SentinelValidationTest {

    /** sentinel 与 countField 同时给 → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BothSentinelAndCount {
        @ProtocolField(order = 1, size = 8) private int n;
        @ProtocolField(order = 2, type = FieldType.LIST,
                countField = "n", elementClass = DnsLabel.class, sentinel = 0x00)
        private java.util.List<DnsLabel> items;
    }

    @Test
    void rejectsSentinelWithCountField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BothSentinelAndCount.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sentinel");
    }

    /** sentinel 与 lengthField 同时给 → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BothSentinelAndLength {
        @ProtocolField(order = 1, size = 8) private int len;
        @ProtocolField(order = 2, type = FieldType.BYTES,
                lengthField = "len", sentinel = 0x00)
        private byte[] data;
    }

    @Test
    void rejectsSentinelWithLengthField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BothSentinelAndLength.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sentinel");
    }

    /** sentinel 越界(>255)→ 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class SentinelOutOfRange {
        @ProtocolField(order = 1, type = FieldType.BYTES, sentinel = 300)
        private byte[] data;
    }

    @Test
    void rejectsSentinelOutOfRange() {
        assertThatThrownBy(() -> new ProtocolCodec<>(SentinelOutOfRange.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sentinel");
    }
}
