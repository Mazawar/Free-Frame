package com.example.netproto.core;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** L2 逃生舱:varint(LEB128)自定义字段编解码,round-trip + 线宽。 */
class CustomFieldCodecTest {

    /** 内联夹具:varint 字段 + sentinel 字符串(与 demo 模块的 HeartbeatMessage 同构)。 */
    @Protocol(id = "varint-fixture")
    public static class VarintEntity {
        @ProtocolField(order = 1, size = 8)
        private int deviceType;

        @ProtocolField(order = 2, custom = VarintCodec.class)
        private Long uptimeMs;

        @ProtocolField(order = 3, sentinel = 0)
        private String hostname;

        public int getDeviceType() { return deviceType; }
        public void setDeviceType(int v) { this.deviceType = v; }
        public Long getUptimeMs() { return uptimeMs; }
        public void setUptimeMs(Long v) { this.uptimeMs = v; }
        public String getHostname() { return hostname; }
        public void setHostname(String v) { this.hostname = v; }
    }

    private final ProtocolCodec<VarintEntity> codec = new ProtocolCodec<>(VarintEntity.class);

    @Test
    void varintRoundTripSmall() {
        VarintEntity e = new VarintEntity();
        e.setDeviceType(3);
        e.setUptimeMs(127L);       // 单字节 varint
        e.setHostname("gw");

        byte[] wire = codec.serialize(e);
        // 1(deviceType) + 1(varint 127) + 2("gw") + 1(终止符) = 5
        assertEquals(5, wire.length);
        assertEquals(127, wire[1] & 0xFF);   // 单字节 varint,无继续位

        VarintEntity back = codec.deserialize(wire);
        assertEquals(127L, back.getUptimeMs());
        assertEquals("gw", back.getHostname());
        assertEquals(3, back.getDeviceType());
    }

    @Test
    void varintRoundTripMultiByte() {
        VarintEntity e = new VarintEntity();
        e.setDeviceType(1);
        e.setUptimeMs(300_000L);   // 3 字节 varint
        e.setHostname("host-01");

        VarintEntity back = codec.deserialize(codec.serialize(e));
        assertEquals(300_000L, back.getUptimeMs());
        assertEquals("host-01", back.getHostname());
        assertEquals(1, back.getDeviceType());
    }

    @Test
    void varintSizeOfGrowsByMagnitude() {
        VarintEntity e = new VarintEntity();
        e.setHostname("");
        e.setUptimeMs(0L);
        assertEquals(1 + 1 + 1, codec.serialize(e).length);       // varint(0)=1B
        e.setUptimeMs(128L);
        assertEquals(1 + 2 + 1, codec.serialize(e).length);       // varint(128)=2B
        e.setUptimeMs(16_384L);
        assertEquals(1 + 3 + 1, codec.serialize(e).length);       // varint(16384)=3B
    }

    @Test
    void customMutuallyExclusiveWithSize() {
        assertThrows(IllegalArgumentException.class, () -> new ProtocolCodec<>(BadMix.class));
    }

    static class BadMix {
        @com.example.netproto.annotation.ProtocolField(order = 1, size = 16, custom = VarintCodec.class)
        private long v;
    }
}
