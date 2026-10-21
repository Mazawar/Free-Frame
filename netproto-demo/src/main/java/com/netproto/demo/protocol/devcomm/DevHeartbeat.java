package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 0x0A 心跳(终端 → 服务端):注册后每 30s 保活。信令体 = 安全信息(4B)。 */
@Data
@ToString
@Protocol(id = "dev-heartbeat", name = "心跳", group = "接入管理")
@BindOn(parent = "dev", when = "signalType == 0x0A")
public class DevHeartbeat {

    @ProtocolField(order = 1, size = 32, label = "安全信息")
    private int security;
}
