package com.netproto.protocols.real.someip;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SOME/IP 头真实帧测试。
 * <p>
 * 头部 16 字节:messageId(32) = serviceId(16) + methodId(16) 位字段拆分;
 * length(32) = 其后全部字节数(= 请求头 8 字节 + payload,不含 messageId 与 length 自身);
 * requestId(32) = clientId(16) + sessionId(16);protoVer(8)=0x01;ifaceVer/msgType/returnCode 各 8bit;
 * payload 由 length 驱动(lengthAdjust = -8)。
 * <p>
 * 权威向量(service 0x1234,method 0x5678,reqId 1,无 payload,任务给定):
 * {@code 12 34 56 78 00 00 00 08 00 00 00 01 01 00 00 00};
 * 带 3B payload 时 length = 0x0B(11)。
 */
class SomeipHeaderTest {

    // ---- 夹具 ----

    @Data
    @Protocol(id = "real-someip-header")
    static class SomeIpHeader {
        /** Message ID 高 16bit:服务 ID。 */
        @ProtocolField(order = 1, size = 16)
        private int serviceId;
        /** Message ID 低 16bit:方法 ID。 */
        @ProtocolField(order = 2, size = 16)
        private int methodId;
        /** Length = requestId(4) + 版本/类型(4) + payload 字节数(= 8 + payload)。 */
        @ProtocolField(order = 3, size = 32)
        private long length;
        /** Request ID 高 16bit:客户端 ID。 */
        @ProtocolField(order = 4, size = 16)
        private int clientId;
        /** Request ID 低 16bit:会话 ID。 */
        @ProtocolField(order = 5, size = 16)
        private int sessionId;
        @ProtocolField(order = 6, size = 8)
        private int protocolVersion = 0x01;
        @ProtocolField(order = 7, size = 8)
        private int interfaceVersion;
        @ProtocolField(order = 8, size = 8)
        private int messageType;
        @ProtocolField(order = 9, size = 8)
        private int returnCode;
        @ProtocolField(order = 10, lengthField = "length", lengthAdjust = -8, type = FieldType.BYTES)
        private byte[] payload = new byte[0];
    }

    // ---- 测试 ----

    /** 无 payload 向量:length=8(仅请求头),messageId/requestId 位字段拆分各就各位。 */
    @Test
    void noPayloadVector() {
        ProtocolCodec<SomeIpHeader> codec = new ProtocolCodec<>(SomeIpHeader.class);
        SomeIpHeader h = new SomeIpHeader();
        h.setServiceId(0x1234);
        h.setMethodId(0x5678);
        h.setLength(8);
        h.setClientId(0);
        h.setSessionId(1);
        h.setProtocolVersion(0x01);

        byte[] wire = codec.serialize(h);
        assertThat(wire).containsExactly(
                0x12, 0x34, 0x56, 0x78,   // messageId = 0x12345678(serviceId<<16 | methodId)
                0x00, 0x00, 0x00, 0x08,   // length = 8(其后全部字节数)
                0x00, 0x00, 0x00, 0x01,   // requestId = 0x00000001(clientId=0, sessionId=1)
                0x01, 0x00, 0x00, 0x00);  // protoVer=1, ifaceVer=0, msgType=0, returnCode=0

        SomeIpHeader back = codec.deserialize(wire);
        assertThat(back.getServiceId()).isEqualTo(0x1234);
        assertThat(back.getMethodId()).isEqualTo(0x5678);
        assertThat(back.getLength()).isEqualTo(8);
        assertThat(back.getClientId()).isZero();
        assertThat(back.getSessionId()).isEqualTo(1);
        assertThat(back.getProtocolVersion()).isEqualTo(1);
        assertThat(back.getPayload()).isEmpty();
        assertThat(codec.serialize(back)).containsExactly(wire);
    }

    /** 带 3B payload:length = 8 + 3 = 11(0x0B),payload 由 lengthAdjust=-8 还原为 3 字节。 */
    @Test
    void threeBytePayloadLengthIsEleven() {
        ProtocolCodec<SomeIpHeader> codec = new ProtocolCodec<>(SomeIpHeader.class);
        SomeIpHeader h = new SomeIpHeader();
        h.setServiceId(0x1234);
        h.setMethodId(0x5678);
        h.setLength(11);
        h.setClientId(0);
        h.setSessionId(1);
        h.setProtocolVersion(0x01);
        h.setPayload(new byte[]{(byte) 0xAA, (byte) 0xBB, (byte) 0xCC});

        byte[] wire = codec.serialize(h);
        assertThat(wire).hasSize(19);
        assertThat(wire).containsExactly(
                0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x0B,
                0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
                0xAA, 0xBB, 0xCC);

        SomeIpHeader back = codec.deserialize(wire);
        assertThat(back.getLength()).isEqualTo(11);
        assertThat(back.getPayload()).containsExactly(0xAA, 0xBB, 0xCC);
        assertThat(codec.serialize(back)).isEqualTo(wire);
    }
}
