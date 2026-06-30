package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TlvValidationTest {

    /** dispatch 类名不存在 → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BadClassContainer {
        @ProtocolField(order = 1, type = FieldType.LIST_TLV,
                tlvEndMarker = 0xFF,
                dispatch = {"1=NonExistentClass"})
        private List<Object> options;
    }

    @Test
    void rejectsUnknownDispatchClass() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BadClassContainer.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("NonExistentClass");
    }

    /** dispatch 格式错(无 =)→ 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BadFormatContainer {
        @ProtocolField(order = 1, type = FieldType.LIST_TLV,
                tlvEndMarker = 0xFF,
                dispatch = {"1SubnetMask"})
        private List<Object> options;
    }

    @Test
    void rejectsBadDispatchFormat() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BadFormatContainer.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("type=ClassName");
    }
}
