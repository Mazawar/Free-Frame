package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * 真实 DNS QName:一串 DnsLabel,以 length=0 的 label(即 0x00 字节)结束。
 * 用 sentinelOn="length", sentinelValue=0 表达元素内 sentinel。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DnsName {

    @ProtocolField(order = 1, type = FieldType.LIST,
            elementClass = DnsLabel.class,
            sentinelOn = "length", sentinelValue = 0)
    private List<DnsLabel> labels = new ArrayList<>();
}
