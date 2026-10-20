package com.netproto.demo.protocol.realworld.kafka;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.nio.charset.StandardCharsets;

/** Kafka 主题名元素:int16 长度前缀字符串。 */
@Data
@ToString
@Protocol(id = "kafka-topic", name = "Kafka 主题", group = "Kafka")
public class KafkaTopic {

    @ProtocolField(order = 1, size = 16)
    private int nameLen;

    @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "nameLen")
    private String name = "";

    public static KafkaTopic of(String name) {
        KafkaTopic t = new KafkaTopic();
        t.setName(name);
        t.setNameLen(name.getBytes(StandardCharsets.UTF_8).length);
        return t;
    }
}
