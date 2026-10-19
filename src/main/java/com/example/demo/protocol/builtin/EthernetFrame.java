package com.example.demo.protocol.builtin;

import com.example.demo.protocol.annotation.Payload;
import com.example.demo.protocol.annotation.Protocol;
import com.example.demo.protocol.annotation.ProtocolField;
import lombok.Data;
import lombok.ToString;

/**
 * Ethernet II 帧(分派树根协议)。
 * dstMac/srcMac 以无符号 48 位存 long(UI 格式化为冒号十六进制);无 VLAN/FCS。
 * payload 由分派引擎交给 etherType 命中的子协议。
 */
@Data
@ToString
@Protocol(id = "ethernet", name = "Ethernet II", builtin = true)
public class EthernetFrame {

    @ProtocolField(order = 1, size = 48)
    private long dstMac;

    @ProtocolField(order = 2, size = 48)
    private long srcMac;

    @ProtocolField(order = 3, size = 16)
    private int etherType;

    @Payload
    private byte[] payload;
}
