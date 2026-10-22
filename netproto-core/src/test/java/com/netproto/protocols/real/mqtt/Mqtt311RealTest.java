package com.netproto.protocols.real.mqtt;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.DynamicSize;
import com.netproto.core.FieldContext;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import com.netproto.core.VarintCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * MQTT 3.1.1 真实报文测试。
 * <p>
 * CONNECT 取规范示例形态:clientId="test"、CleanSession、KeepAlive=60:
 * {@code 10 10 00 04 4D 51 54 54 04 02 00 3C 00 04 74 65 73 74}。
 * 另覆盖 PINGREQ 与 PUBLISH(QoS0)。
 * Remaining Length 为 LEB128 varint(内置 VarintCodec)。
 */
class Mqtt311RealTest {

    // ---- 夹具 ----

    @Data
    @Protocol(id = "real-mqtt-connect")
    static class Connect {
        @ProtocolField(order = 1, size = 4)
        private int type = 1;
        @ProtocolField(order = 2, size = 4)
        private int flags;
        @ProtocolField(order = 3, custom = VarintCodec.class)
        private Long remainingLength;
        @ProtocolField(order = 4, size = 16)
        private int protoNameLen = 4;
        @ProtocolField(order = 5, type = FieldType.STRING, lengthField = "protoNameLen")
        private String protoName = "MQTT";
        @ProtocolField(order = 6, size = 8)
        private int level = 4;
        /** 00000010 = CleanSession。 */
        @ProtocolField(order = 7, size = 8)
        private int connectFlags = 0x02;
        @ProtocolField(order = 8, size = 16)
        private int keepAlive = 60;
        @ProtocolField(order = 9, size = 16)
        private int clientIdLen;
        @ProtocolField(order = 10, type = FieldType.STRING, lengthField = "clientIdLen")
        private String clientId;
    }

    @Data
    @Protocol(id = "real-mqtt-pingreq")
    static class PingReq {
        @ProtocolField(order = 1, size = 4)
        private int type = 12;
        @ProtocolField(order = 2, size = 4)
        private int flags;
        @ProtocolField(order = 3, custom = VarintCodec.class)
        private Long remainingLength = 0L;
    }

    @Data
    @Protocol(id = "real-mqtt-publish")
    static class Publish implements DynamicSize {
        @ProtocolField(order = 1, size = 4)
        private int type = 3;
        @ProtocolField(order = 2, size = 4)
        private int flags;
        @ProtocolField(order = 3, custom = VarintCodec.class)
        private Long remainingLength;
        @ProtocolField(order = 4, size = 16)
        private int topicLen;
        @ProtocolField(order = 5, type = FieldType.STRING, lengthField = "topicLen")
        private String topic;
        /** payload = remainingLength − 2 − topicLen(钩子算动态长度)。 */
        @ProtocolField(order = 6, type = FieldType.BYTES)
        private byte[] payload = new byte[0];

        @Override
        public long computeSize(String fieldName, FieldContext ctx) {
            if (!"payload".equals(fieldName)) {
                return -1;
            }
            int topicBytes = ((String) ctx.get("topic")).getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            return (ctx.getInt("remainingLength") - 2 - topicBytes) * 8L;
        }
    }

    // ---- 测试 ----

    /** 规范示例 CONNECT 字节级断言。 */
    @Test
    void connectFrameMatchesSpecExample() {
        ProtocolCodec<Connect> codec = new ProtocolCodec<>(Connect.class);
        Connect c = new Connect();
        c.setRemainingLength(16L);
        c.setClientId("test");
        c.setClientIdLen(4);
        byte[] wire = codec.serialize(c);
        assertThat(wire).containsExactly(
                0x10, 0x10,
                0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,
                0x04, 0x02, 0x00, 0x3C,
                0x00, 0x04, 0x74, 0x65, 0x73, 0x74);

        Connect back = codec.deserialize(wire);
        assertThat(back.getProtoName()).isEqualTo("MQTT");
        assertThat(back.getKeepAlive()).isEqualTo(60);
        assertThat(back.getClientId()).isEqualTo("test");
        assertThat(back.getRemainingLength()).isEqualTo(16L);
    }

    /** PINGREQ:C0 00。 */
    @Test
    void pingreqFrame() {
        ProtocolCodec<PingReq> codec = new ProtocolCodec<>(PingReq.class);
        assertThat(codec.serialize(new PingReq())).containsExactly((byte) 0xC0, 0x00);
    }

    /** PUBLISH QoS0:topic "a" + payload "hi" → 30 05 00 01 61 68 69(payload 长度=剩余)。 */
    @Test
    void publishQos0Frame() {
        ProtocolCodec<Publish> codec = new ProtocolCodec<>(Publish.class);
        Publish p = new Publish();
        p.setRemainingLength(5L);
        p.setTopic("a");
        p.setTopicLen(1);
        p.setPayload("hi".getBytes());
        byte[] wire = codec.serialize(p);
        assertThat(wire).containsExactly(0x30, 0x05, 0x00, 0x01, 0x61, 0x68, 0x69);

        Publish back = codec.deserialize(wire);
        assertThat(back.getTopic()).isEqualTo("a");
        assertThat(back.getPayload()).containsExactly("hi".getBytes());
    }
}
