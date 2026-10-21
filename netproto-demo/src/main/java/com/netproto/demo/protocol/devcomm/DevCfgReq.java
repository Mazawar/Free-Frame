package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 0x01 配置请求(终端 → 服务端):上电第一步。信令体 = 安全信息(4B,未分配全 0)。 */
@Data
@ToString
@Protocol(id = "dev-cfg-req", name = "配置请求", group = "接入管理")
@BindOn(parent = "dev", when = "signalType == 0x01")
public class DevCfgReq {

    @ProtocolField(order = 1, size = 32, label = "安全信息")
    private int security;
}
