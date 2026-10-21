package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x26 清单应答(平台 → 终端):确认清单收到。
 * 信令体 = 应答结果(1B)。
 */
@Data
@ToString
@Protocol(id = "pd-list-ack", name = "清单应答", group = "智能配电")
@BindOn(parent = "pd", when = "signalType == 0x26")
public class PdListAck {

    /** 00 成功 / 01 失败。 */
    @ProtocolField(order = 1, size = 8, label = "应答结果")
    private int result;
}
