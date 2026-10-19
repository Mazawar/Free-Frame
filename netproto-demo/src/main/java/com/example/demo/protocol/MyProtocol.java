package com.example.demo.protocol;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Payload;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * 自定义协议定义 —— 只需一个 POJO + 注解,无需手写序列化。
 * 通过 @BindOn 挂到 UDP 9999 端口,自动加入自顶向下分派树。
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
@Protocol(id = "my-app", name = "My App Protocol")
@BindOn(parent = "udp", when = "dstPort == 9999 || srcPort == 9999")
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
