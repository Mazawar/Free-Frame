package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x04 注销应答(平台 → 终端):确认吊销。
 * 信令体 = 注销结果(1B);流水号在公共头内回显。
 */
@Data
@ToString
@Protocol(id = "pd-logout-resp", name = "注销应答", group = "智能配电")
@BindOn(parent = "pd", when = "signalType == 0x04")
public class PdLogoutResp {

    /** 00 成功 / 01 失败。 */
    @ProtocolField(order = 1, size = 8, label = "注销结果")
    private int result;
}
