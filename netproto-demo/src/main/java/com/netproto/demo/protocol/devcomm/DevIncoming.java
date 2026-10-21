package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 0x07 来电(服务端 → 被叫)。信令体 = 安全信息(4B) + 主叫设备(3B)。 */
@Data
@ToString
@Protocol(id = "dev-incoming", name = "来电", group = "呼叫控制")
@BindOn(parent = "dev", when = "signalType == 0x07")
public class DevIncoming {

    @ProtocolField(order = 1, size = 32, label = "安全信息")
    private int security;

    @ProtocolField(order = 2, size = 24, label = "主叫设备")
    private int caller = 1;
}
