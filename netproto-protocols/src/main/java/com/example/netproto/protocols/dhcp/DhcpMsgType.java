package com.example.netproto.protocols.dhcp;

import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.annotation.Protocol;
import lombok.Data;
import lombok.ToString;

/** DHCP Option 53:消息类型(1 字节)。value 实体。 */
@Data
@ToString
@Protocol(id = "dhcp-msg-type")
public class DhcpMsgType {
    @ProtocolField(order = 1, size = 8)
    private int type;
}
