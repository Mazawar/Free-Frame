package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * GXTP 配置下发(msgType=3):异质 TLV 列表 —— type 决定 value 实体类型。
 * <pre>
 *  +------+------+------------------------+     +------+
 *  | type | len  | value(按 type 解析)    | ... | 0x00 |  ← 结束标记
 *  +------+------+------------------------+     +------+
 *  type=1 → GxConfNumber(数值项)  type=2 → GxConfString(文本项)
 *  type=3 → GxConfBlob(密钥/证书等原始字节项)   未知 type 自动跳过
 * </pre>
 * 演示机制:LIST_TLV 异质分派(dispatch 表)、tlvEndMarker 结束标记、未知 type 容错跳过。
 */
@Data
@ToString
@Protocol(id = "gx-config", name = "GXTP 配置下发")
@BindOn(parent = "gxtp", when = "msgType == 3")
public class GxConfigBody {

    @ProtocolField(order = 1, type = FieldType.LIST_TLV,
            tlvEndMarker = 0x00,
            dispatch = {"1=GxConfNumber", "2=GxConfString", "3=GxConfBlob"})
    private List<Object> items = new ArrayList<>();

    public static GxConfigBody of(List<Object> items) {
        GxConfigBody b = new GxConfigBody();
        b.setItems(new ArrayList<>(items));
        return b;
    }
}
