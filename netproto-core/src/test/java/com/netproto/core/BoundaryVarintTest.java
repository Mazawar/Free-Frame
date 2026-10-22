package com.netproto.core;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 能力边界测试:变长整数族。
 * <ul>
 *   <li>LEB128(Protobuf / MQTT Remaining Length 同款)—— 内置 VarintCodec(L2 逃生舱示例);</li>
 *   <li>MQTT 式固定头:type/flags 半字节 + varint 剩余长度 + 长度驱动载荷;</li>
 *   <li>QUIC 前缀定长 varint(高 2bit 选 1/2/4/8 字节)与 CoAP nibble 逃逸 —— 声明式不可表达,
 *       需 L2 自定义(报告项,不入正测);</li>
 *   <li>zigzag(Protobuf sint)—— 需自定义变换(报告项)。</li>
 * </ul>
 */
class BoundaryVarintTest {

    // ---- 夹具 ----

    @Data
    @Protocol(id = "b-varint")
    static class VarintFrame {
        @ProtocolField(order = 1, custom = VarintCodec.class)
        private Long v;
    }

    /** MQTT 式固定头:1B type/flags + varint remaining length + 载荷。 */
    @Data
    @Protocol(id = "b-mqtt-like")
    static class MqttLikeFrame {
        @ProtocolField(order = 1, size = 4)
        private int type;
        @ProtocolField(order = 2, size = 4)
        private int flags;
        @ProtocolField(order = 3, custom = VarintCodec.class)
        private Long remainingLength;
        @ProtocolField(order = 4, lengthField = "remainingLength", type = FieldType.BYTES)
        private byte[] payload = new byte[0];
    }

    // ---- 测试 ----

    @Test
    void leb128RoundTripsAcrossMagnitudes() {
        ProtocolCodec<VarintFrame> codec = new ProtocolCodec<>(VarintFrame.class);
        long[] values = {0, 1, 127, 128, 300, 16383, 16384,
                0x7FFFFFFFL, 0x1_0000_0000L, Long.MAX_VALUE};
        for (long v : values) {
            VarintFrame f = new VarintFrame();
            f.setV(v);
            byte[] wire = codec.serialize(f);
            VarintFrame back = codec.deserialize(wire);
            assertThat(back.getV()).as("value %d", v).isEqualTo(v);
        }
    }

    /** Protobuf 标准向量:300 → 0xAC 0x02。 */
    @Test
    void leb128KnownWireEncoding() {
        ProtocolCodec<VarintFrame> codec = new ProtocolCodec<>(VarintFrame.class);
        VarintFrame f = new VarintFrame();
        f.setV(300L);
        assertThat(codec.serialize(f)).containsExactly(0xAC, 0x02);
    }

    /** 超过 64bit 的 varint 流(10 字节全续位)→ 干净拒绝。 */
    @Test
    void leb128OverflowFailsCleanly() {
        ProtocolCodec<VarintFrame> codec = new ProtocolCodec<>(VarintFrame.class);
        byte[] bad = new byte[11];
        java.util.Arrays.fill(bad, (byte) 0x80);
        bad[10] = 0x01;
        RuntimeException ex = assertThrows(RuntimeException.class, () -> codec.deserialize(bad));
        assertThat(ex.getCause()).hasMessageContaining("varint too long");
    }

    /** MQTT 式:半字节 type/flags + varint 长度驱动载荷,大载荷走多字节长度。 */
    @Test
    void mqttLikeFixedHeaderRoundTrip() {
        ProtocolCodec<MqttLikeFrame> codec = new ProtocolCodec<>(MqttLikeFrame.class);
        MqttLikeFrame f = new MqttLikeFrame();
        f.setType(3);    // PUBLISH
        f.setFlags(0);
        f.setRemainingLength(200L);   // > 127 → 2 字节 varint
        byte[] payload = new byte[200];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i * 7);
        }
        f.setPayload(payload);
        byte[] wire = codec.serialize(f);
        assertThat(wire).hasSize(3 + 200);   // 1B 头 + 2B varint + 200B
        assertThat(wire[0]).isEqualTo((byte) 0x30);
        assertThat(wire[1] & 0xFF).isEqualTo(0xC8);   // 200 & 0x7F | 0x80
        assertThat(wire[2]).isEqualTo((byte) 0x01);

        MqttLikeFrame back = codec.deserialize(wire);
        assertThat(back.getRemainingLength()).isEqualTo(200L);
        assertThat(back.getPayload()).containsExactly(payload);
    }
}
