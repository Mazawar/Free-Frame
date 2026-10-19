package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Payload;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * GXTP 遥测上报(msgType=2):网关聚合多个传感器读数批量上报。
 * 演示机制:countField 驱动的嵌套对象列表 + @Payload 预留尾部
 * (列表计数消费主体,剩余字节留在本层不再下降)。
 */
@Data
@ToString
@Protocol(id = "gx-telemetry", name = "GXTP 遥测上报")
@BindOn(parent = "gxtp", when = "msgType == 2")
public class GxTelemetryReport {

    @ProtocolField(order = 1, size = 32, type = FieldType.UNSIGNED)
    private long gatewayId;

    @ProtocolField(order = 2, size = 16)
    private int sensorCount;

    @ProtocolField(order = 3, type = FieldType.LIST,
            countField = "sensorCount", elementClass = GxSensor.class)
    private List<GxSensor> sensors = new ArrayList<>();

    /** 预留扩展尾(本次为空)。 */
    @Payload
    private byte[] tail;

    public static GxTelemetryReport of(long gatewayId, List<GxSensor> sensors) {
        GxTelemetryReport r = new GxTelemetryReport();
        r.setGatewayId(gatewayId);
        r.setSensors(new ArrayList<>(sensors));
        r.setSensorCount(sensors.size());
        return r;
    }
}
