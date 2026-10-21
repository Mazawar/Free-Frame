package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 0x0B 心跳应答(服务端 → 终端):保活确认。信令体 = 安全信息(4B) + 保活结果(1B)。 */
@Data
@ToString
@Protocol(id = "dev-heartbeat-resp", name = "心跳应答", group = "接入管理")
@BindOn(parent = "dev", when = "signalType == 0x0B")
public class DevHeartbeatResp {

    @ProtocolField(order = 1, size = 32, label = "安全信息")
    private int security;

    /** AA 成功 / 01 失败。 */
    @ProtocolField(order = 2, size = 8, label = "保活结果")
    private int result = 0xAA;
}
