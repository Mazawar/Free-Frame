package com.netproto.protocols.dhcp;

import com.netproto.annotation.ProtocolField;
import com.netproto.annotation.Protocol;
import lombok.Data;
import lombok.ToString;

/** DHCP Option 3:路由器(4 字节 IP)。value 实体。 */
@Data
@ToString
@Protocol(id = "router")
public class Router {
    @ProtocolField(order = 1, size = 32)
    private int address;
}
