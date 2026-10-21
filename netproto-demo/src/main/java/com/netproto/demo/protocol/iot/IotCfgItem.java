package com.netproto.demo.protocol.iot;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 配置条目(LIST 元素,16B):设备id(4B) + 设备名称(6B) + 设备归属地(4B) + 保留(2B)。 */
@Data
@ToString
@Protocol(id = "iot-cfg-item", name = "配置条目", group = "物联网")
public class IotCfgItem {

    @ProtocolField(order = 1, size = 32, label = "设备id")
    private int deviceId;

    /** 6B 名称按原始字节展示。 */
    @ProtocolField(order = 2, size = 48, label = "设备名称")
    private byte[] name = new byte[6];

    @ProtocolField(order = 3, size = 32, label = "设备归属地")
    private int region;

    @ProtocolField(order = 4, size = 16, label = "保留")
    private int reserved;

    public static IotCfgItem of(int id, byte[] name, int region) {
        IotCfgItem i = new IotCfgItem();
        i.setDeviceId(id);
        i.setName(name);
        i.setRegion(region);
        return i;
    }
}
