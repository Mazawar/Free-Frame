package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SentinelBytesTest {

    @Data
    @ProtocolPacket(port = 0)
    public static class CStringPacket {
        @ProtocolField(order = 1, type = FieldType.BYTES, sentinel = 0x00)
        private byte[] text;

        public CStringPacket() {
            this.text = new byte[0];
        }
    }

    @Test
    void roundTripsSentinelBlob() {
        ProtocolCodec<CStringPacket> codec = new ProtocolCodec<>(CStringPacket.class);

        CStringPacket p = new CStringPacket();
        p.setText("Hi".getBytes());   // 48 69

        byte[] out = codec.serialize(p);
        // "Hi" + 0x00 结束标记
        assertThat(out).containsExactly(0x48, 0x69, 0x00);

        CStringPacket parsed = codec.deserialize(out);
        assertThat(parsed.getText()).containsExactly(0x48, 0x69);  // 不含 0x00
    }

    @Test
    void roundTripsEmptySentinelBlob() {
        ProtocolCodec<CStringPacket> codec = new ProtocolCodec<>(CStringPacket.class);

        CStringPacket p = new CStringPacket();
        p.setText(new byte[0]);  // 空,直接以标记开始

        byte[] out = codec.serialize(p);
        assertThat(out).containsExactly(0x00);  // 仅标记

        CStringPacket parsed = codec.deserialize(out);
        assertThat(parsed.getText()).isEmpty();
    }
}
