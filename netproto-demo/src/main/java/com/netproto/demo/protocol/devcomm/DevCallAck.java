package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 0x08 呼叫应答(被叫 → 服务端)。信令体 = 安全信息(4B) + 呼叫结果(1B) + 主叫设备(3B)。 */
@Data
@ToString
@Protocol(id = "dev-call-ack", name = "呼叫应答", group = "呼叫控制")
@BindOn(parent = "dev", when = "signalType == 0x08")
public class DevCallAck {

    @ProtocolField(order = 1, size = 32, label = "安全信息")
    private int security;

    /** 01 接收 / 02 拒绝。 */
    @ProtocolField(order = 2, size = 8, label = "呼叫结果")
    private int result = 1;

    @ProtocolField(order = 3, size = 24, label = "主叫设备")
    private int caller = 1;
}
