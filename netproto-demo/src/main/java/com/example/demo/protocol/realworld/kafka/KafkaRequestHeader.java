package com.example.demo.protocol.realworld.kafka;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import com.example.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * Kafka 请求头(现代中间件/游戏服务端同款形态,TCP 9092)。
 * <pre>
 *  | length(32b,含自身后 4B 起的全部) | apiKey(16b) | apiVersion(16b) | correlationId(32b) |
 *  | clientIdLen(16b) + clientId | body... |
 * </pre>
 * 验证点:int32 长度前缀(含头)、apiKey 版本化分派、int16 长度前缀字符串。
 */
@Data
@ToString
@Protocol(id = "kafka", name = "Kafka 请求", group = "Kafka")
@BindOn(parent = "tcp", when = "dstPort == 9092 || srcPort == 9092")
public class KafkaRequestHeader implements PayloadAware {

    /** 后续总长度(不含本字段),组装期自动。 */
    @ProtocolField(order = 1, size = 32)
    private long length;

    /** 0=Produce 1=Fetch 3=Metadata:子协议分派字段。 */
    @ProtocolField(order = 2, size = 16)
    private int apiKey;

    @ProtocolField(order = 3, size = 16)
    private int apiVersion;

    @ProtocolField(order = 4, size = 32)
    private long correlationId;

    @ProtocolField(order = 5, size = 16)
    private int clientIdLen;

    @ProtocolField(order = 6, type = FieldType.STRING, lengthField = "clientIdLen")
    private String clientId = "";

    @Override
    public void onPayload(byte[] inner) {
        // length = apiKey(2)+apiVersion(2)+correlationId(4)+clientIdLen(2) + clientId + body
        this.length = 10 + clientIdLen + inner.length;
    }

    public static KafkaRequestHeader of(int apiKey, int apiVersion, long correlationId, String clientId) {
        KafkaRequestHeader h = new KafkaRequestHeader();
        h.setApiKey(apiKey);
        h.setApiVersion(apiVersion);
        h.setCorrelationId(correlationId);
        h.setClientId(clientId);
        h.setClientIdLen(clientId.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
        return h;
    }
}
