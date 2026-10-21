package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x23 告警上报(终端 → 平台):越限告警。
 * 信令体 = 告警类型(1B) + 告警级别(1B) + 告警值(2B)。
 */
@Data
@ToString
@Protocol(id = "pd-alarm-report", name = "告警上报", group = "智能配电")
@BindOn(parent = "pd", when = "signalType == 0x23")
public class PdAlarmReport {

    /** 01 过压 / 02 欠压 / 03 过流 / 04 过温。 */
    @ProtocolField(order = 1, size = 8, label = "告警类型")
    private int alarmType = 1;

    /** 01 紧急 / 02 重要 / 03 次要。 */
    @ProtocolField(order = 2, size = 8, label = "告警级别")
    private int alarmLevel = 2;

    /** 触发值,默认 3000 = 300.0V。 */
    @ProtocolField(order = 3, size = 16, label = "告警值")
    private int alarmValue = 3000;
}
