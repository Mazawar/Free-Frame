package com.example.demo.protocol.dhcp;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import lombok.Data;
import lombok.ToString;

/** DHCP Option 53:消息类型(1 字节)。value 实体。 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DhcpMsgType {
    @ProtocolField(order = 1, size = 8)
    private int type;
}
