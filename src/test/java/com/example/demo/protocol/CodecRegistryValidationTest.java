package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CodecRegistryValidationTest {

    @Data
    @ProtocolPacket(port = 7006)
    public static class BackwardRef {
        @ProtocolField(order = 1, size = 8)
        private int len;
        @ProtocolField(order = 2, type = FieldType.BYTES, lengthField = "len")
        private byte[] payload; // payload order=2 引用 len order=1 — 合法
    }

    @Data
    @ProtocolPacket(port = 7007)
    public static class NonExistentRef {
        @ProtocolField(order = 1, size = 8)
        private int len;
        @ProtocolField(order = 2, type = FieldType.BYTES, lengthField = "ghost")
        private byte[] payload; // 引用不存在的字段
    }

    @Test
    void rejectsNonExistentLengthField() {
        assertThatThrownBy(() -> new ProtocolCodec<>(NonExistentRef.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ghost");
    }

    @Test
    void acceptsValidLengthRef() {
        // BackwardRef: payload(order2) 引用 len(order1) — 合法,不抛异常
        assertThatCode(() -> new ProtocolCodec<>(BackwardRef.class))
                .doesNotThrowAnyException();
    }
}
