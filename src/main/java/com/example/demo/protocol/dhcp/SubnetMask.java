package com.example.demo.protocol.dhcp;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.Protocol;
import lombok.Data;
import lombok.ToString;

/** DHCP Option 1:子网掩码(4 字节 IP)。value 实体,只含 value 部分。 */
@Data
@ToString
@Protocol(id = "subnet-mask")
public class SubnetMask {
    @ProtocolField(order = 1, size = 32)
    private int mask;
}
