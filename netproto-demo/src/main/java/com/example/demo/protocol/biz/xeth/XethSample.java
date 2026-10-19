package com.example.demo.protocol.biz.xeth;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/** 遥测采样点:tsMs(32b) + value(16b 无符号,千分比定点)。untilEnd 元素须定长。 */
@Data
@ToString
@Protocol(id = "xeth-sample", name = "XETH 采样点")
public class XethSample {

    @ProtocolField(order = 1, size = 32, type = FieldType.UNSIGNED)
    private long tsMs;

    @ProtocolField(order = 2, size = 16, type = FieldType.UNSIGNED)
    private int value;

    public static XethSample of(long tsMs, int value) {
        XethSample s = new XethSample();
        s.setTsMs(tsMs);
        s.setValue(value);
        return s;
    }
}
