package com.example.demo.protocol.biz.xeth;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/** XETH 选项条目(嵌套元素实体,无 @BindOn:不进分派树,只作 LIST 元素)。 */
@Data
@ToString
@Protocol(id = "xeth-option", name = "XETH 选项")
public class XethOption {

    @ProtocolField(order = 1, size = 8)
    private int optType;

    @ProtocolField(order = 2, size = 8)
    private int optLen;

    @ProtocolField(order = 3, type = FieldType.BYTES, lengthField = "optLen")
    private byte[] value = new byte[0];

    public static XethOption of(int type, byte[] value) {
        XethOption o = new XethOption();
        o.setOptType(type);
        o.setValue(value);
        o.setOptLen(value.length);
        return o;
    }
}
