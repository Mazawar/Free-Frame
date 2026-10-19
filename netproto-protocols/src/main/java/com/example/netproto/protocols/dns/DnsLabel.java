package com.example.netproto.protocols.dns;

import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * DNS label:1 字节长度 + 变长内容。用作 LIST 元素。
 * 自定边界:content 由 lengthField="length" 定长度,不会「吃剩余字节」。
 */
@Data
@ToString
@Protocol(id = "dns-label")
public class DnsLabel {

    @ProtocolField(order = 1, size = 8)
    private int length;

    @ProtocolField(order = 2, type = FieldType.BYTES, lengthField = "length")
    private byte[] content;

    public DnsLabel() {
        this.content = new byte[0];
    }

    /** 便捷构造:从字符串生成 label。 */
    public DnsLabel(String s) {
        byte[] b = s.getBytes();
        this.length = b.length;
        this.content = b;
    }
}
