package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 设备配置条目(LIST 元素,9B):设备ID(3B) + 设备序列号(4B) + 设备标识(2B)。 */
@Data
@ToString
@Protocol(id = "dev-equip-entry", name = "设备配置条目", group = "设备通信")
public class DevEquipEntry {

    @ProtocolField(order = 1, size = 24, label = "设备ID")
    private int deviceId;

    @ProtocolField(order = 2, size = 32, label = "设备序列号")
    private int serial;

    @ProtocolField(order = 3, size = 16, label = "设备标识")
    private int tag;

    public static DevEquipEntry of(int id, int serial, int tag) {
        DevEquipEntry e = new DevEquipEntry();
        e.setDeviceId(id);
        e.setSerial(serial);
        e.setTag(tag);
        return e;
    }
}
