package com.example.netproto.protocols.dns;

import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.core.FieldType;
import com.example.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CodecListValidationTest {

    /** 无自定边界的元素:最后一个字段变长且无 lengthField/countField → 非法。 */
    @Data
    @Protocol(id = "port-0")
    public static class BadElement {
        @ProtocolField(order = 1, size = 8) private int mark;
        @ProtocolField(order = 2, type = FieldType.BYTES) private byte[] rest;
    }

    @Data
    @Protocol(id = "port-0")
    public static class BadListContainer {
        @ProtocolField(order = 1, size = 8) private int n;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "n", elementClass = BadElement.class)
        private List<BadElement> items;
    }

    @Test
    void rejectsElementWithoutSelfBoundary() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BadListContainer.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("boundary");
    }

    /** countField 引用不存在的字段 → 非法。 */
    @Data
    @Protocol(id = "port-0")
    public static class UnknownCountContainer {
        @ProtocolField(order = 1, size = 8) private int realCount;
        @ProtocolField(order = 2, type = FieldType.LIST, countField = "ghost", elementClass = DnsLabel.class)
        private List<DnsLabel> items;
    }

    @Test
    void rejectsUnknownCountField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(UnknownCountContainer.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ghost");
    }

    /** countField 前向引用(order 更大)→ 非法。 */
    @Data
    @Protocol(id = "port-0")
    public static class ForwardCountContainer {
        @ProtocolField(order = 1, type = FieldType.LIST, countField = "n", elementClass = DnsLabel.class)
        private List<DnsLabel> items;
        @ProtocolField(order = 2, size = 8) private int n;
    }

    @Test
    void rejectsForwardCountField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(ForwardCountContainer.class))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
