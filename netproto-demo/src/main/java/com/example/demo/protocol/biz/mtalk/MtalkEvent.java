package com.example.demo.protocol.biz.mtalk;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/** 事件元素:eventType + dataLen 定界变长数据(untilEnd 列表元素的「自定边界」)。 */
@Data
@ToString
@Protocol(id = "mtalk-event", name = "MTALK 事件")
public class MtalkEvent {

    @ProtocolField(order = 1, size = 8)
    private int eventType;

    @ProtocolField(order = 2, size = 8)
    private int dataLen;

    @ProtocolField(order = 3, type = FieldType.BYTES, lengthField = "dataLen")
    private byte[] data = new byte[0];

    public static MtalkEvent of(int eventType, byte[] data) {
        MtalkEvent e = new MtalkEvent();
        e.setEventType(eventType);
        e.setData(data);
        e.setDataLen(data.length);
        return e;
    }
}
