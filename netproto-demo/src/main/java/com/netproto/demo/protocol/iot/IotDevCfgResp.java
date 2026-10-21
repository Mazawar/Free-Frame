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
 * 0x02 设备配置响应(设备 → 平台):条目数 + 条目 × 1B + 保留(2B) + CRC(2B)。
 */
@Data
@ToString
@Protocol(id = "iot-dev-cfg-resp", name = "设备配置响应", group = "设备协议")
@BindOn(parent = "iot", when = "frameType == 0x02")
public class IotDevCfgResp {

    @ProtocolField(order = 1, size = 8, label = "条目数")
    private int entryCount = 1;

    @ProtocolField(order = 2, type = FieldType.LIST,
            elementClass = IotRespItem.class, countField = "entryCount")
    private List<IotRespItem> results = new ArrayList<>(List.of(IotRespItem.ok()));

    @ProtocolField(order = 3, size = 16, label = "保留")
    private int reserved;

    @ProtocolField(order = 4, size = 16, label = "CRC")
    private int crc = 0x55AA;
}
