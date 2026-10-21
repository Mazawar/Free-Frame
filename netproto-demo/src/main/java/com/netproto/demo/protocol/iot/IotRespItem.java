package com.netproto.demo.protocol.iot;

import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/** 响应条目(LIST 元素,1B):响应结果。 */
@Data
@ToString
@Protocol(id = "iot-resp-item", name = "响应条目", group = "物联网")
public class IotRespItem {

    /** 00 成功 / 01 失败。 */
    @ProtocolField(order = 1, size = 8, label = "响应结果")
    private int result;

    public static IotRespItem ok() {
        IotRespItem i = new IotRespItem();
        i.setResult(0);
        return i;
    }
}
