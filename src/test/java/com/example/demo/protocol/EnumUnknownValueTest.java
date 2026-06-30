package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.core.ProtocolEnum;
import com.example.demo.protocol.core.UnknownEnumValue;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EnumUnknownValueTest {

    /** 只定义 1/6/17,89 未覆盖。 */
    public enum Proto implements ProtocolEnum {
        ICMP(1), TCP(6), UDP(17);
        private final int v;
        Proto(int v) { this.v = v; }
        @Override public int value() { return v; }
    }

    @Data
    @ProtocolPacket(port = 0)
    public static class Pkt {
        @ProtocolField(order = 1, size = 8, enumClass = Proto.class)
        private ProtocolEnum protocol;
    }

    @Test
    void unknownValueDeserializesToPlaceholder() {
        ProtocolCodec<Pkt> codec = new ProtocolCodec<>(Pkt.class);

        // 89 = OSPF,enum 里没有
        Pkt parsed = codec.deserialize(new byte[]{(byte) 89});
        Object protocol = parsed.getProtocol();
        assertThat(protocol).isInstanceOf(UnknownEnumValue.class);
        assertThat(((UnknownEnumValue) protocol).value()).isEqualTo(89);
    }

    @Test
    void unknownValueRoundTripsWithZeroLoss() {
        ProtocolCodec<Pkt> codec = new ProtocolCodec<>(Pkt.class);

        // 读 89 → UnknownEnumValue → 再序列化 → 仍是 89(零丢失)
        Pkt parsed = codec.deserialize(new byte[]{(byte) 89});
        byte[] reserialized = codec.serialize(parsed);
        assertThat(reserialized).containsExactly((byte) 89);
    }
}
