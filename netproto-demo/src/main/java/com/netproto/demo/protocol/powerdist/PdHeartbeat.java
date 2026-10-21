package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x05 心跳保活(终端 → 平台):注册后每 30s 一次,令牌认证失败平台回「令牌无效」。
 * 信令体 = 运行状态(1B)。
 */
@Data
@ToString
@Protocol(id = "pd-heartbeat", name = "心跳保活", group = "接入管理")
@BindOn(parent = "pd", when = "signalType == 0x05")
public class PdHeartbeat {

    /** 00 正常 / 01 告警 / 02 检修。 */
    @ProtocolField(order = 1, size = 8, label = "运行状态")
    private int runStatus;
}
