package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x03 注销(终端 → 平台):下线,平台吊销令牌。
 * 信令体 = 注销原因(1B)。
 */
@Data
@ToString
@Protocol(id = "pd-logout", name = "注销", group = "智能配电")
@BindOn(parent = "pd", when = "signalType == 0x03")
public class PdLogout {

    /** 01 正常注销。 */
    @ProtocolField(order = 1, size = 8, label = "注销原因")
    private int reason = 1;
}
