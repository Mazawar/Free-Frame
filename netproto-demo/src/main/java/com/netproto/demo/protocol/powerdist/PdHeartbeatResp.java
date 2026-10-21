package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x06 心跳应答(平台 → 终端):保活确认;令牌不符回 02 令牌无效。
 * 信令体 = 保活结果(1B)。
 */
@Data
@ToString
@Protocol(id = "pd-heartbeat-resp", name = "心跳应答", group = "智能配电")
@BindOn(parent = "pd", when = "signalType == 0x06")
public class PdHeartbeatResp {

    /** 00 成功 / 01 失败 / 02 令牌无效 / 03 未注册。 */
    @ProtocolField(order = 1, size = 8, label = "保活结果")
    private int result;
}
