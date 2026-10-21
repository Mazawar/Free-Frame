package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 终端状态条目(LIST 元素,5B):终端地址(4B) + 运行状态(1B)。
 */
@Data
@ToString
@Protocol(id = "pd-dev-status", name = "终端状态", group = "智能配电")
public class PdDevStatus {

    @ProtocolField(order = 1, size = 32, label = "终端地址")
    private int addr;

    /** 00 正常 / 01 告警 / 02 检修。 */
    @ProtocolField(order = 2, size = 8, label = "运行状态")
    private int runStatus;

    public static PdDevStatus of(int addr, int status) {
        PdDevStatus d = new PdDevStatus();
        d.setAddr(addr);
        d.setRunStatus(status);
        return d;
    }
}
