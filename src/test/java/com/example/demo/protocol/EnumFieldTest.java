package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.core.ProtocolEnum;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EnumFieldTest {

    public enum IpProtocol implements ProtocolEnum {
        ICMP(1), TCP(6), UDP(17);
        private final int v;
        IpProtocol(int v) { this.v = v; }
        @Override public int value() { return v; }
    }

    @Data
    @ProtocolPacket(port = 0)
    public static class ProtoPacket {
        @ProtocolField(order = 1, size = 8) private IpProtocol protocol;
    }

    @Test
    void roundTripsKnownEnumValue() {
        ProtocolCodec<ProtoPacket> codec = new ProtocolCodec<>(ProtoPacket.class);

        ProtoPacket original = new ProtoPacket();
        original.setProtocol(IpProtocol.UDP);  // 17 = 0x11

        byte[] out = codec.serialize(original);
        assertThat(out).containsExactly(0x11);

        ProtoPacket parsed = codec.deserialize(out);
        assertThat(parsed.getProtocol()).isEqualTo(IpProtocol.UDP);
    }

    @Test
    void roundTripsAllEnumValues() {
        ProtocolCodec<ProtoPacket> codec = new ProtocolCodec<>(ProtoPacket.class);
        for (IpProtocol p : IpProtocol.values()) {
            ProtoPacket original = new ProtoPacket();
            original.setProtocol(p);
            byte[] out = codec.serialize(original);
            assertThat(out).containsExactly((byte) p.value());
            assertThat(codec.deserialize(out).getProtocol()).isEqualTo(p);
        }
    }
}
