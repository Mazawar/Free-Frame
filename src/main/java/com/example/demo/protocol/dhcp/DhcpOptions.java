package com.example.demo.protocol.dhcp;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/** DHCP Options 段:异质 TLV,type=0xFF 结束。 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DhcpOptions {

    @ProtocolField(order = 1, type = FieldType.LIST_TLV,
            tlvEndMarker = 0xFF,
            dispatch = {"1=SubnetMask", "3=Router", "53=DhcpMsgType"})
    private List<Object> options = new ArrayList<>();
}
