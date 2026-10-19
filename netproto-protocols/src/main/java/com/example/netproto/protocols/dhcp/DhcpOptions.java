package com.example.netproto.protocols.dhcp;

import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/** DHCP Options 段:异质 TLV,type=0xFF 结束。 */
@Data
@ToString
@Protocol(id = "dhcp-options")
public class DhcpOptions {

    @ProtocolField(order = 1, type = FieldType.LIST_TLV,
            tlvEndMarker = 0xFF,
            dispatch = {"1=SubnetMask", "3=Router", "53=DhcpMsgType"})
    private List<Object> options = new ArrayList<>();
}
