package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/** 配置项·数值(TLV type=1,value 实体只含 value 部分):confId + 32b 数值,定长 6 字节。 */
@Data
@ToString
@Protocol(id = "gx-conf-number", name = "GXTP 配置·数值")
public class GxConfNumber {

    @ProtocolField(order = 1, size = 16)
    private int confId;

    @ProtocolField(order = 2, size = 32, type = FieldType.UNSIGNED)
    private long value;

    public static GxConfNumber of(int confId, long value) {
        GxConfNumber n = new GxConfNumber();
        n.setConfId(confId);
        n.setValue(value);
        return n;
    }
}
