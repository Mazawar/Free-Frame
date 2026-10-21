package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 0x02 配置数据(服务端 → 终端):服务器IP + 心跳周期。信令体 = 安全信息(4B) + 服务器IP(4B) + 心跳周期(2B)。 */
@Data
@ToString
@Protocol(id = "dev-cfg-data", name = "配置数据", group = "接入管理")
@BindOn(parent = "dev", when = "signalType == 0x02")
public class DevCfgData {

    @ProtocolField(order = 1, size = 32, label = "安全信息")
    private int security;

    /** 点分十进制按 4B 整数承载,默认 192.168.0.1。 */
    @ProtocolField(order = 2, size = 32, label = "服务器IP")
    private int serverIp = 0xC0A80001;

    /** 秒,默认 60。 */
    @ProtocolField(order = 3, size = 16, label = "心跳周期")
    private int heartbeatCycle = 60;
}
