package com.netproto.demo.protocol.realworld.kafka;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * Kafka Metadata 请求(apiKey=3):int32 数组前缀 + 主题名列表 ——
 * 「count 前缀驱动、每元素再带自身长度前缀字符串」的现代中间件标准循环形态。
 */
@Data
@ToString
@Protocol(id = "kafka-metadata", name = "Kafka Metadata 请求", group = "Kafka")
@BindOn(parent = "kafka", when = "apiKey == 3")
public class KafkaMetadataReq {

    /** 主题个数(int32 前缀,-1 = null 数组,这里取 ≥0)。 */
    @ProtocolField(order = 1, size = 32, type = FieldType.UNSIGNED)
    private long topicsCount;

    @ProtocolField(order = 2, type = FieldType.LIST,
            countField = "topicsCount", elementClass = KafkaTopic.class)
    private List<KafkaTopic> topics = new ArrayList<>();

    public static KafkaMetadataReq of(KafkaTopic... topics) {
        KafkaMetadataReq r = new KafkaMetadataReq();
        r.setTopics(new ArrayList<>(List.of(topics)));
        r.setTopicsCount(topics.length);
        return r;
    }
}
