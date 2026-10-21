package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 0x05 注册响应(服务端 → 终端):分配安全信息。信令体 = 安全信息(4B) + 注册结果(1B)。 */
@Data
@ToString
@Protocol(id = "dev-reg-resp", name = "注册响应", group = "接入管理")
@BindOn(parent = "dev", when = "signalType == 0x05")
public class DevRegResp {

    @ProtocolField(order = 1, size = 32, label = "安全信息")
    private int security = 0x11223344;

    /** AA 成功 / 01 失败。 */
    @ProtocolField(order = 2, size = 8, label = "注册结果")
    private int result = 0xAA;
}
