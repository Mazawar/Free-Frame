package com.example.demo.protocol.core;

import com.example.demo.protocol.HeartbeatMessage;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** L2 逃生舱:HeartbeatMessage.uptimeMs 走 VarintCodec(LEB128),round-trip + 线宽。 */
class CustomFieldCodecTest {

    private final ProtocolCodec<HeartbeatMessage> codec = new ProtocolCodec<>(HeartbeatMessage.class);

    @Test
    void varintRoundTripSmall() {
        HeartbeatMessage msg = new HeartbeatMessage();
        msg.setDeviceType(3);
        msg.setUptimeMs(127L);       // 单字节 varint
        msg.setHostname("gw");

        byte[] wire = codec.serialize(msg);
        // 1(deviceType) + 1(varint 127) + 2("gw") + 1(终止符) = 5
        assertEquals(5, wire.length);
        assertEquals(127, wire[1] & 0xFF);   // 单字节 varint,无继续位

        HeartbeatMessage back = codec.deserialize(wire);
        assertEquals(127L, back.getUptimeMs());
        assertEquals("gw", back.getHostname());
        assertEquals(3, back.getDeviceType());
    }

    @Test
    void varintRoundTripMultiByte() {
        HeartbeatMessage msg = new HeartbeatMessage();
        msg.setDeviceType(1);
        msg.setUptimeMs(300_000L);   // 3 字节 varint
        msg.setHostname("host-01");

        byte[] wire = codec.serialize(msg);
        HeartbeatMessage back = codec.deserialize(wire);
        assertEquals(300_000L, back.getUptimeMs());
        assertEquals(msg, back);
    }

    @Test
    void varintSizeOfGrowsByMagnitude() {
        HeartbeatMessage msg = new HeartbeatMessage();
        msg.setHostname("");
        msg.setUptimeMs(0L);
        assertEquals(1 + 1 + 1, codec.serialize(msg).length);       // varint(0)=1B
        msg.setUptimeMs(128L);
        assertEquals(1 + 2 + 1, codec.serialize(msg).length);       // varint(128)=2B
        msg.setUptimeMs(16_384L);
        assertEquals(1 + 3 + 1, codec.serialize(msg).length);       // varint(16384)=3B
    }

    @Test
    void customMutuallyExclusiveWithSize() {
        // size 与 custom 混用必须在构建期报错
        assertThrows(IllegalArgumentException.class, () -> new ProtocolCodec<>(BadMix.class));
    }

    static class BadMix {
        @com.example.demo.protocol.annotation.ProtocolField(order = 1, size = 16, custom = VarintCodec.class)
        private long v;
    }
}
