package com.example.demo.protocol;

import com.example.demo.protocol.annotation.Payload;
import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import lombok.Data;
import lombok.ToString;

/**
 * 自定义协议定义 —— 只需一个 POJO + 注解，无需手写序列化。
 * <p>
 * 报文结构：
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Version (1B) |  Type (1B)    |        Reserved (2B)         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                   Sequence ID (4B)                          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                   Payload Data (变长)                          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
@Data
@ToString
@ProtocolPacket(port = 9999)
public class MyProtocol {

    @ProtocolField(order = 1, size = 8)
    private byte version = 1;

    @ProtocolField(order = 2, size = 8)
    private byte type;

    @ProtocolField(order = 3, size = 16)
    private short reserved;

    @ProtocolField(order = 4, size = 32)
    private int sequenceId;

    @Payload
    private byte[] payloadData;

    public MyProtocol() {
        this.payloadData = new byte[0];
    }
}
