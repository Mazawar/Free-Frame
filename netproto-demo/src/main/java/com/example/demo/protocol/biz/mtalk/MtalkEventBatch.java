package com.example.demo.protocol.biz.mtalk;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * MTALK 事件批量上报(cmd=0x20):「读到帧尾为止」的事件流。
 * 演示机制:untilEnd 列表,元素靠自身 dataLen 定界(变长元素的自定边界)。
 */
@Data
@ToString
@Protocol(id = "mtalk-events", name = "MTALK 事件批量")
@BindOn(parent = "mtalk", when = "cmd == 0x20")
public class MtalkEventBatch {

    @ProtocolField(order = 1, type = FieldType.LIST,
            elementClass = MtalkEvent.class, untilEnd = true)
    private List<MtalkEvent> events = new ArrayList<>();

    public static MtalkEventBatch of(List<MtalkEvent> events) {
        MtalkEventBatch b = new MtalkEventBatch();
        b.setEvents(new ArrayList<>(events));
        return b;
    }
}
