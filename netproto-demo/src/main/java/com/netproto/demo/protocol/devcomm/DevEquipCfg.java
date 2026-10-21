package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * 设备配置(XML 中 p_mvakevcbt7dw,无信令类型,以帧头 FF A1 起始):
 * 线路上 FF 落在 DevFrame.signalType 位(0xFF 分派),本实体从 A1 起读。
 * 信令体 = 帧头低字节(1B)=A1 + 命令字(1B) + 条目数(1B)
 *        + 条目数 × (设备ID 3B + 设备序列号 4B + 设备标识 2B)。
 */
@Data
@ToString
@Protocol(id = "dev-equip-cfg", name = "设备配置", group = "接入管理")
@BindOn(parent = "dev", when = "signalType == 0xFF")
public class DevEquipCfg {

    /** 帧头低字节(高字节 FF 已作分派选择子)。 */
    @ProtocolField(order = 1, size = 8, label = "帧头")
    private int frameTailMark = 0xA1;

    @ProtocolField(order = 2, size = 8, label = "命令字")
    private int cmd = 1;

    @ProtocolField(order = 3, size = 8, label = "配置条目数")
    private int entryCount = 1;

    @ProtocolField(order = 4, type = FieldType.LIST,
            elementClass = DevEquipEntry.class, countField = "entryCount")
    private List<DevEquipEntry> entries = new ArrayList<>(List.of(DevEquipEntry.of(1, 2, 3)));
}
