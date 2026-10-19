package com.example.demo.protocol.biz.xeth;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * XETH 遥测报文(channel=1):deviceId + 「读到帧尾为止」的采样序列。
 * 演示机制:untilEnd 循环(元素自定边界 6 字节)、无 count 字段的列表驱动。
 */
@Data
@ToString
@Protocol(id = "xeth-tele", name = "XETH 遥测")
@BindOn(parent = "xeth", when = "channel == 1")
public class XethTelemetry {

    @ProtocolField(order = 1, size = 16, type = FieldType.UNSIGNED)
    private int deviceId;

    @ProtocolField(order = 2, type = FieldType.LIST,
            elementClass = XethSample.class, untilEnd = true)
    private List<XethSample> samples = new ArrayList<>();

    public static XethTelemetry of(int deviceId, List<XethSample> samples) {
        XethTelemetry t = new XethTelemetry();
        t.setDeviceId(deviceId);
        t.setSamples(new ArrayList<>(samples));
        return t;
    }
}
