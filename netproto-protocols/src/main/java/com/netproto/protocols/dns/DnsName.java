package com.netproto.protocols.dns;

import com.netproto.annotation.ProtocolField;
import com.netproto.annotation.Protocol;
import com.netproto.core.FieldType;
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
@Protocol(id = "dns-name")
public class DnsName {

    @ProtocolField(order = 1, type = FieldType.LIST,
            elementClass = DnsLabel.class,
            sentinelOn = "length", sentinelValue = 0)
    private List<DnsLabel> labels = new ArrayList<>();
}
