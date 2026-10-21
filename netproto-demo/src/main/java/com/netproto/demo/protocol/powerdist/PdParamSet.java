package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x11 参数设置(终端 → 平台):上报运行参数修改。
 * 信令体 = 采集周期(2B) + 告警阈值(2B)。
 */
@Data
@ToString
@Protocol(id = "pd-param-set", name = "参数设置", group = "智能配电")
@BindOn(parent = "pd", when = "signalType == 0x11")
public class PdParamSet {

    /** 秒,默认 60(0x003C)。 */
    @ProtocolField(order = 1, size = 16, label = "采集周期")
    private int sampleCycle = 0x3C;

    /** 默认 400(0x0190)。 */
    @ProtocolField(order = 2, size = 16, label = "告警阈值")
    private int alarmThreshold = 0x190;
}
