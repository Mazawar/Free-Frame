package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * 0x25 设备清单上报(终端 → 平台)。
 * 信令体 = 终端个数(1B) + 终端个数 × 状态条目(5B:地址+状态) + 校验和(2B)。
 * 演示点:countField 计数驱动 LIST + 尾随定长字段(与参数查询响应同构)。
 */
@Data
@ToString
@Protocol(id = "pd-dev-list", name = "设备清单上报", group = "智能配电")
@BindOn(parent = "pd", when = "signalType == 0x25")
public class PdDevListReport {

    @ProtocolField(order = 1, size = 8, label = "终端个数")
    private int devCount = 2;

    @ProtocolField(order = 2, type = FieldType.LIST,
            elementClass = PdDevStatus.class, countField = "devCount")
    private List<PdDevStatus> devices = new ArrayList<>(List.of(
            PdDevStatus.of(1, 0), PdDevStatus.of(2, 0)));

    /** 尾随校验和(源协议为固定 55AA 占位)。 */
    @ProtocolField(order = 3, size = 16, label = "校验和")
    private int checksum = 0x55AA;
}
