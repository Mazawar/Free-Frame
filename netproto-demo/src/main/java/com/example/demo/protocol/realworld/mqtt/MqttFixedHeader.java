package com.example.demo.protocol.realworld.mqtt;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.PayloadAware;
import com.example.netproto.core.VarintCodec;
import lombok.Data;
import lombok.ToString;

/**
 * MQTT 3.1.1 固定头(物联网事实标准,TCP 1883)。
 * <pre>
 *  | type(4b) | DUP(1b) | QoS(2b) | RETAIN(1b) | 剩余长度 varint(1-4B) |
 * </pre>
 * 验证点:varint 变长头(VarintCodec = MQTT 同款 base-128 连续编码)、
 * type 字段分派、位拆分 flags、剩余长度 onPayload 自动回填。
 */
@Data
@ToString
@Protocol(id = "mqtt", name = "MQTT 3.1.1", group = "MQTT")
@BindOn(parent = "tcp", when = "dstPort == 1883 || srcPort == 1883")
public class MqttFixedHeader implements PayloadAware {

    /** 1=CONNECT 2=CONNACK 3=PUBLISH 8=SUBSCRIBE 9=SUBACK 13=PINGREQ。 */
    @ProtocolField(order = 1, size = 4)
    private int type;

    @ProtocolField(order = 2, size = 1)
    private int dup;

    @ProtocolField(order = 3, size = 2)
    private int qos;

    @ProtocolField(order = 4, size = 1)
    private int retain;

    /** 剩余长度(可变头+载荷),varint 1-4 字节,组装期自动。 */
    @ProtocolField(order = 5, custom = VarintCodec.class)
    private Long remainingLength;

    @Override
    public void onPayload(byte[] inner) {
        this.remainingLength = (long) inner.length;
    }

    public static MqttFixedHeader of(int type, int qos) {
        MqttFixedHeader h = new MqttFixedHeader();
        h.setType(type);
        h.setQos(qos);
        return h;
    }
}
