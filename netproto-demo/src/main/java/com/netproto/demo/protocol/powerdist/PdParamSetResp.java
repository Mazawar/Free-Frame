package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x12 参数设置应答(平台 → 终端):确认参数生效。
 * 信令体 = 设置结果(1B)。
 */
@Data
@ToString
@Protocol(id = "pd-param-set-resp", name = "参数设置应答", group = "参数配置")
@BindOn(parent = "pd", when = "signalType == 0x12")
public class PdParamSetResp {

    /** 00 成功 / 01 失败。 */
    @ProtocolField(order = 1, size = 8, label = "设置结果")
    private int result;
}
