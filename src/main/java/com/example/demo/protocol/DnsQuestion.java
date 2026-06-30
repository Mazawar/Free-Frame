package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * DNS Question 段(count 驱动变体):labelCount 个 label。
 * 注意:真实 DNS 用 0x00 结束标记,非 count;此处是 Phase 2a 的 count 驱动子集。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DnsQuestion {

    @ProtocolField(order = 1, size = 8)
    private int labelCount;

    @ProtocolField(order = 2, type = FieldType.LIST,
            countField = "labelCount", elementClass = DnsLabel.class)
    private List<DnsLabel> labels = new ArrayList<>();
}
