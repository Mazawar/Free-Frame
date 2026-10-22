package com.netproto.protocols.real.mqttsn;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.DynamicSize;
import com.netproto.core.FieldCodec;
import com.netproto.core.FieldContext;
import com.netproto.core.FieldType;
import com.netproto.core.BitCursor;
import com.netproto.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 真实协议测试 3:MQTT-SN v1.2 的 Length 字段语义。
 * <p>
 * 规范语义(MQTT-SN v1.2 §2.1):Length = 整个报文长度(含 Length 字段自身);
 * 报文长 &gt; 255 字节时,首字节固定为 0x01(转义标记),后跟 2 字节大端真实长度(总头 3B)。
 * <p>
 * 向量出处:MQTT-SN v1.2 规范 §5.2.2 SEARCHGW(len=3、type=0x01、radius=1);
 * CONNECT(§5.3.4)长报文走 0x01 转义 —— 任务权威断言:首 4 字节 01 01 2A 04、总长 298(0x012A)。
 * 按 §5.3.4 布局(type+flags+protocolId+duration 共 5B,ClientId 至报文尾),
 * 总长 298 对应 ClientId 290 字节(298 − 3B 转义头 − 5B 固定字段;任务书写的 293 与 298
 * 在规范布局下互斥,以线格式断言为准)。
 * <p>
 * 逃生舱说明:Length 字段的「转义形式依赖自身宽度」是声明式 lengthField 表达不了的
 * (长度字段字节数随总长变化),用 L2 自定义 FieldCodec 只接管 len 字段:
 * 读 = 首字节,0x01 再读 2B;写 = 按总长决定 1B 或 0x01+2B;字段值恒为真实总长。
 * ClientId「至报文尾」由 DynamicSize 钩子按 totalLen 推出(两种长度形态通吃)。
 */
class MqttSnRealTest {

    /**
     * MQTT-SN Length 字段(L2 逃生舱):字段值 = 真实总长(含 Length 字段自身)。
     * 总长 1..255 → 单字节;256..65535 → 0x01 + 2 字节大端(总头 3B)。
     */
    public static class MqttSnLengthCodec implements FieldCodec<Integer> {
        @Override
        public Integer read(BitCursor cursor, FieldContext ctx, int remainingBytes) {
            int first = (int) cursor.readBits(8) & 0xFF;
            if (first == 0x01) {
                return (int) cursor.readBits(16);   // 转义:2 字节 BE 真实总长
            }
            return first;
        }

        @Override
        public void write(BitCursor cursor, FieldContext ctx, Integer value) {
            int v = value == null ? 0 : value;
            if (v >= 0x0100 && v <= 0xFFFF) {
                cursor.writeBits(0x01, 8);
                cursor.writeBits(v, 16);
            } else {
                cursor.writeBits(v, 8);
            }
        }

        @Override
        public long sizeOf(Integer value) {
            int v = value == null ? 0 : value;
            return v >= 0x0100 && v <= 0xFFFF ? 24 : 8;
        }
    }

    /** SEARCHGW(§5.2.2):Length + MsgType(0x01) + Radius。 */
    @Data
    @Protocol(id = "real-mqttsn-searchgw")
    static class SearchGw {
        @ProtocolField(order = 1, custom = MqttSnLengthCodec.class)
        private Integer totalLen;
        @ProtocolField(order = 2, size = 8)
        private int type;
        @ProtocolField(order = 3, size = 8)
        private int radius;
    }

    /** CONNECT(§5.3.4):Length + MsgType(0x04) + Flags + ProtocolId + Duration + ClientId(至报文尾)。 */
    @Data
    @Protocol(id = "real-mqttsn-connect")
    static class Connect implements DynamicSize {
        @ProtocolField(order = 1, custom = MqttSnLengthCodec.class)
        private Integer totalLen;
        @ProtocolField(order = 2, size = 8)
        private int type = 0x04;
        /** QoS0、无 will、clean session → 0x00。 */
        @ProtocolField(order = 3, size = 8)
        private int flags;
        @ProtocolField(order = 4, size = 8)
        private int protocolId = 0x01;
        /** keepalive = 60 秒。 */
        @ProtocolField(order = 5, size = 16)
        private int duration = 60;
        @ProtocolField(order = 6, type = FieldType.BYTES)
        private byte[] clientId;

        /** clientId = 总长 − Length 字段宽度(1B 或 3B 转义) − 5B(type/flags/protocolId/duration)。 */
        @Override
        public long computeSize(String fieldName, FieldContext ctx) {
            if (!"clientId".equals(fieldName)) {
                return -1;
            }
            long total = ctx.getInt("totalLen");
            int lenBytes = total > 0xFF ? 3 : 1;
            return (total - lenBytes - 5) * 8L;
        }
    }

    // ---- 测试 ----

    /** SEARCHGW 短形式向量:len=3 单字节,报文 03 01 01(Length 含自身)。 */
    @Test
    void searchGwShortFormMatchesVector() {
        ProtocolCodec<SearchGw> codec = new ProtocolCodec<>(SearchGw.class);
        SearchGw msg = new SearchGw();
        msg.setTotalLen(3);   // 1(len) + 1(type) + 1(radius)
        msg.setType(0x01);
        msg.setRadius(1);

        byte[] wire = codec.serialize(msg);
        assertThat(wire).containsExactly(0x03, 0x01, 0x01);
        assertThat(wire.length).isEqualTo(msg.getTotalLen());   // Length 语义 = 整个报文长度

        SearchGw back = codec.deserialize(wire);
        assertThat(back.getTotalLen()).isEqualTo(3);
        assertThat(back.getType()).isEqualTo(0x01);
        assertThat(back.getRadius()).isEqualTo(1);
    }

    /** CONNECT 长形式:首字节 0x01 转义 + 2B BE 总长 298(0x012A)+ type 0x04;总长一致 + round-trip。 */
    @Test
    void connectLongFormEscapesToThreeByteHeader() {
        ProtocolCodec<Connect> codec = new ProtocolCodec<>(Connect.class);

        byte[] clientId = new byte[290];   // 298 − 3(转义头) − 5(固定字段)
        Arrays.fill(clientId, (byte) 'x');
        Connect msg = new Connect();
        msg.setTotalLen(3 + 5 + clientId.length);   // = 298 = 0x012A
        msg.setClientId(clientId);

        byte[] wire = codec.serialize(msg);
        // 权威断言:首 4 字节 01 01 2A 04(转义 + 总长 0x012A + MsgType CONNECT)
        assertThat(wire[0]).isEqualTo((byte) 0x01);
        assertThat(wire[1]).isEqualTo((byte) 0x01);
        assertThat(wire[2]).isEqualTo((byte) 0x2A);
        assertThat(wire[3]).isEqualTo((byte) 0x04);
        assertThat(wire).hasSize(298);   // 总长与 Length 字段一致
        // 固定字段:flags=0、protocolId=1、duration=60(0x003C)
        assertThat(wire[4]).isEqualTo((byte) 0x00);
        assertThat(wire[5]).isEqualTo((byte) 0x01);
        assertThat(wire[6]).isEqualTo((byte) 0x00);
        assertThat(wire[7]).isEqualTo((byte) 0x3C);
        // ClientId 到报文尾,全 'x'(0x78)
        assertThat(wire[8]).isEqualTo((byte) 0x78);
        assertThat(wire[297]).isEqualTo((byte) 0x78);

        Connect back = codec.deserialize(wire);
        assertThat(back.getTotalLen()).isEqualTo(298);
        assertThat(back.getType()).isEqualTo(0x04);
        assertThat(back.getProtocolId()).isEqualTo(0x01);
        assertThat(back.getDuration()).isEqualTo(60);
        assertThat(back.getClientId()).hasSize(290);
        assertThat(back.getClientId()).containsOnly((byte) 'x');
        assertThat(codec.serialize(back)).containsExactly(wire);   // round-trip 字节稳定
    }

    /** 同一实体短形式 CONNECT(总长 ≤ 255):单字节 Length,无转义;round-trip。 */
    @Test
    void connectShortFormStaysSingleByteLength() {
        ProtocolCodec<Connect> codec = new ProtocolCodec<>(Connect.class);
        byte[] clientId = "sensor-1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);   // 8B
        Connect msg = new Connect();
        msg.setTotalLen(1 + 5 + clientId.length);   // = 14
        msg.setClientId(clientId);

        byte[] wire = codec.serialize(msg);
        assertThat(wire).hasSize(14);
        assertThat(wire[0]).isEqualTo((byte) 0x0E);   // 单字节 Length,首字节非 0x01
        assertThat(wire[1]).isEqualTo((byte) 0x04);
        assertThat(wire.length).isEqualTo(msg.getTotalLen());

        Connect back = codec.deserialize(wire);
        assertThat(back.getTotalLen()).isEqualTo(14);
        assertThat(back.getClientId()).containsExactly(clientId);
    }
}
