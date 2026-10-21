package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x21 状态上报(终端 → 平台):周期上报电气量。
 * 信令体 = 电压(2B) + 电流(2B) + 温度(1B) + 运行状态(1B)。
 */
@Data
@ToString
@Protocol(id = "pd-status-report", name = "状态上报", group = "智能配电")
@BindOn(parent = "pd", when = "signalType == 0x21")
public class PdStatusReport {

    /** 0.1V 单位,默认 2500 = 250.0V。 */
    @ProtocolField(order = 1, size = 16, label = "电压")
    private int voltage = 2500;

    /** 0.1A 单位,默认 100 = 10.0A。 */
    @ProtocolField(order = 2, size = 16, label = "电流")
    private int current = 100;

    /** ℃,默认 25。 */
    @ProtocolField(order = 3, size = 8, label = "温度")
    private int temp = 25;

    /** 00 正常 / 01 告警 / 02 检修。 */
    @ProtocolField(order = 4, size = 8, label = "运行状态")
    private int runStatus;
}
