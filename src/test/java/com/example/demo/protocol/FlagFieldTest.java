package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.core.ProtocolFlag;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class FlagFieldTest {

    public enum TcpFlag implements ProtocolFlag {
        FIN(0x01), SYN(0x02), RST(0x04), PSH(0x08), ACK(0x10), URG(0x20);
        private final int m;
        TcpFlag(int m) { this.m = m; }
        @Override public int mask() { return m; }
    }

    @Data
    @ProtocolPacket(port = 0)
    public static class FlagPacket {
        @ProtocolField(order = 1, size = 8, flagClass = TcpFlag.class)
        private Set<TcpFlag> flags;
    }

    @Test
    void roundTripsCombinedFlags() {
        ProtocolCodec<FlagPacket> codec = new ProtocolCodec<>(FlagPacket.class);

        FlagPacket original = new FlagPacket();
        original.setFlags(EnumSet.of(TcpFlag.SYN, TcpFlag.ACK));  // 0x02 | 0x10 = 0x12

        byte[] out = codec.serialize(original);
        assertThat(out).containsExactly(0x12);

        FlagPacket parsed = codec.deserialize(out);
        assertThat(parsed.getFlags()).containsExactlyInAnyOrder(TcpFlag.SYN, TcpFlag.ACK);
    }

    @Test
    void roundTripsSingleAndEmptyFlags() {
        ProtocolCodec<FlagPacket> codec = new ProtocolCodec<>(FlagPacket.class);

        // 单 flag
        FlagPacket single = new FlagPacket();
        single.setFlags(EnumSet.of(TcpFlag.SYN));
        assertThat(codec.serialize(single)).containsExactly(0x02);
        assertThat(codec.deserialize(new byte[]{0x02}).getFlags()).containsExactly(TcpFlag.SYN);

        // 空 flag
        FlagPacket empty = new FlagPacket();
        empty.setFlags(EnumSet.noneOf(TcpFlag.class));
        assertThat(codec.serialize(empty)).containsExactly(0x00);
        assertThat(codec.deserialize(new byte[]{0x00}).getFlags()).isEmpty();
    }

    @Test
    void reservedBitsAreIgnored() {
        ProtocolCodec<FlagPacket> codec = new ProtocolCodec<>(FlagPacket.class);

        // 0x52 = SYN(0x02) | ACK(0x10) | 保留位(0x40,flagClass 未定义)
        FlagPacket parsed = codec.deserialize(new byte[]{0x52});
        assertThat(parsed.getFlags()).containsExactlyInAnyOrder(TcpFlag.SYN, TcpFlag.ACK);  // 0x40 忽略

        // 序列化回去:已知 flag 零丢失,保留位丢失 → 0x12(声明的 C1 行为)
        byte[] reserialized = codec.serialize(parsed);
        assertThat(reserialized).containsExactly(0x12);
    }
}
