package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 0x13 参数查询(终端 → 平台):查询运行参数。
 * 信令体 = 查询个数(1B)。
 */
@Data
@ToString
@Protocol(id = "pd-param-query", name = "参数查询", group = "参数配置")
@BindOn(parent = "pd", when = "signalType == 0x13")
public class PdParamQuery {

    @ProtocolField(order = 1, size = 8, label = "查询个数")
    private int queryCount = 3;
}
