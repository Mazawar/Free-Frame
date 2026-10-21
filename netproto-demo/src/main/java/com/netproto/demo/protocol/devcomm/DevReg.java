package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 0x04 注册(终端 → 服务端):开机注册,安全信息全 0。信令体 = 安全信息(4B)。 */
@Data
@ToString
@Protocol(id = "dev-reg", name = "注册", group = "接入管理")
@BindOn(parent = "dev", when = "signalType == 0x04")
public class DevReg {

    @ProtocolField(order = 1, size = 32, label = "安全信息")
    private int security;
}
