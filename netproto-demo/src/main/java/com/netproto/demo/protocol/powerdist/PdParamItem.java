package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 参数条目(LIST 元素,3B):参数编号(1B) + 参数值(2B)。
 * 01 采集周期 / 02 告警阈值 / 03 心跳间隔。
 */
@Data
@ToString
@Protocol(id = "pd-param-item", name = "参数条目", group = "智能配电")
public class PdParamItem {

    @ProtocolField(order = 1, size = 8, label = "参数编号")
    private int paramId;

    @ProtocolField(order = 2, size = 16, label = "参数值")
    private int value;

    public static PdParamItem of(int id, int value) {
        PdParamItem i = new PdParamItem();
        i.setParamId(id);
        i.setValue(value);
        return i;
    }
}
