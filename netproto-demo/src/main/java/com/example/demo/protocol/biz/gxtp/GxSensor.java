package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/** 传感器读数元素:sensorType + valueRaw(千分比定点,无符号 16b)。定长 3 字节。 */
@Data
@ToString
@Protocol(id = "gx-sensor", name = "GXTP 传感器读数")
public class GxSensor {

    @ProtocolField(order = 1, size = 8)
    private int sensorType;

    @ProtocolField(order = 2, size = 16, type = FieldType.UNSIGNED)
    private int valueRaw;

    public static GxSensor of(int sensorType, int valueRaw) {
        GxSensor s = new GxSensor();
        s.setSensorType(sensorType);
        s.setValueRaw(valueRaw);
        return s;
    }
}
