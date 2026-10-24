package com.netproto.demo.protocol.iot;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * 0x01 设备配置(平台 → 设备):条目数 + 条目 × 16B + 保留(2B) + CRC(2B)。
 * 演示点:count 驱动列表 + 列表后的尾随保留/CRC 字段(叶子协议,自定界)。
 */
@Data
@ToString
@Protocol(id = "iot-dev-cfg", name = "设备配置", group = "设备协议")
@BindOn(parent = "iot", when = "frameType == 0x01")
public class IotDevCfg {

    @ProtocolField(order = 1, size = 8, label = "条目数")
    private int entryCount = 1;

    @ProtocolField(order = 2, type = FieldType.LIST,
            elementClass = IotCfgItem.class, countField = "entryCount")
    private List<IotCfgItem> entries = new ArrayList<>(List.of(IotCfgItem.of(1, "SL-001".getBytes(), 0x0102)));

    @ProtocolField(order = 3, size = 16, label = "保留")
    private int reserved;

    /** 固定 55AA 占位,非计算 CRC——真实实现应走 @ChecksumField。 */
    @ProtocolField(order = 4, size = 16, label = "CRC(占位)")
    private int crc = 0x55AA;
}
