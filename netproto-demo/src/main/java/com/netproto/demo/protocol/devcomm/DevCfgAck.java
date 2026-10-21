package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 0x03 配置应答(终端 → 服务端):收到配置数据自动回。信令体 = 安全信息(4B) + 应答结果(1B)。 */
@Data
@ToString
@Protocol(id = "dev-cfg-ack", name = "配置应答", group = "接入管理")
@BindOn(parent = "dev", when = "signalType == 0x03")
public class DevCfgAck {

    @ProtocolField(order = 1, size = 32, label = "安全信息")
    private int security;

    /** AA 成功 / 01 失败。 */
    @ProtocolField(order = 2, size = 8, label = "应答结果")
    private int result = 0xAA;
}
