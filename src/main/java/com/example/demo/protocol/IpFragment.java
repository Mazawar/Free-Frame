package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * IP 分片(简化):totalLen 字段决定 payload 字节数。
 * payload 占 totalLen - 20 字节(20 是 IP 头固定开销),用 lengthAdjust=-20 表达。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class IpFragment {

    @ProtocolField(order = 1, size = 16)
    private int totalLen;

    @ProtocolField(order = 2, type = FieldType.BYTES,
            lengthField = "totalLen", lengthAdjust = -20)
    private byte[] payload;

    public IpFragment() {
        this.payload = new byte[0];
    }
}
