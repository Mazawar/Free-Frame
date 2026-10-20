package com.example.demo.protocol.realworld.s7;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/** S7 读变量 Job(msgType=1):function 0x04 + 定长 12 字节 Item 列表。 */
@Data
@ToString
@Protocol(id = "s7-read-job", name = "S7 读变量请求")
@BindOn(parent = "s7", when = "msgType == 1")
public class S7ReadJob {

    /** 0x04 = Read Var。 */
    @ProtocolField(order = 1, size = 8)
    private int function = 0x04;

    @ProtocolField(order = 2, size = 8)
    private int itemCount;

    @ProtocolField(order = 3, type = FieldType.LIST,
            countField = "itemCount", elementClass = S7Item.class)
    private List<S7Item> items = new ArrayList<>();

    public static S7ReadJob of(S7Item... items) {
        S7ReadJob j = new S7ReadJob();
        j.setItems(new ArrayList<>(List.of(items)));
        j.setItemCount(items.length);
        return j;
    }
}
