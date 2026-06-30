package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.LengthUnit;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CodecLengthRefTest {

    @Data
    @ProtocolPacket(port = 7003)
    public static class LengthRefPacket {
        @ProtocolField(order = 1, size = 8)  private int length;     // 后续 payload 字节数
        @ProtocolField(order = 2, type = FieldType.BYTES, lengthField = "length")
        private byte[] payload;
    }

    @Test
    void roundTripByteLengthRef() {
        ProtocolCodec<LengthRefPacket> codec = new ProtocolCodec<>(LengthRefPacket.class);
        LengthRefPacket original = new LengthRefPacket();
        original.setLength(3);
        original.setPayload(new byte[]{0x10, 0x20, 0x30});

        byte[] out = codec.serialize(original);
        // 结构:1字节length + 3字节payload = 4字节
        assertThat(out).containsExactly(0x03, 0x10, 0x20, 0x30);

        LengthRefPacket parsed = codec.deserialize(out);
        assertThat(parsed.getLength()).isEqualTo(3);
        assertThat(parsed.getPayload()).containsExactly(0x10, 0x20, 0x30);
    }

    @Data
    @ProtocolPacket(port = 7004)
    public static class BitLengthRefPacket {
        @ProtocolField(order = 1, size = 8)  private int len;        // 后续 bits 数
        @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "len", lengthUnit = LengthUnit.BITS)
        private String text;
    }

    @Test
    void roundTripBitLengthRefString() {
        ProtocolCodec<BitLengthRefPacket> codec = new ProtocolCodec<>(BitLengthRefPacket.class);
        BitLengthRefPacket original = new BitLengthRefPacket();
        String s = "Hi"; // 2 ASCII 字符 = 16 bits
        original.setLen(s.getBytes().length * 8); // 16
        original.setText(s);

        byte[] out = codec.serialize(original);
        // 1字节len + 2字节"Hi"
        assertThat(out).containsExactly(0x10, (byte) 'H', (byte) 'i');

        BitLengthRefPacket parsed = codec.deserialize(out);
        assertThat(parsed.getText()).isEqualTo("Hi");
    }
}
