package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * DNS Name(sentinel 驱动变体):一串 DnsLabel,以 0x00 结束。
 * 与 Phase 2a 的 DnsQuestion(count 驱动)对比:这里用 sentinel=0x00。
 * 注意:真实 DNS 的 0x00 是「长度0的label」语义(元素内判定,Phase 2c);
 *       Phase 2b 视 0x00 为独立结束字节,简化但能覆盖大部分场景。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DnsNameSentinel {

    @ProtocolField(order = 1, type = FieldType.LIST,
            elementClass = DnsLabel.class, sentinel = 0x00)
    private List<DnsLabel> labels = new ArrayList<>();
}
