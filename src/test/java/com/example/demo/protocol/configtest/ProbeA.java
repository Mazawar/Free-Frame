package com.example.demo.protocol.configtest;

import com.example.demo.protocol.annotation.BindOn;
import com.example.demo.protocol.annotation.Protocol;
import com.example.demo.protocol.annotation.ProtocolField;
import lombok.Data;

/** 自动装配测试夹具:挂在 UDP 7777 的用户协议。 */
@Data
@Protocol(id = "probe-a", name = "Probe A")
@BindOn(parent = "udp", when = "dstPort == 7777 || srcPort == 7777")
public class ProbeA {

    @ProtocolField(order = 1, size = 8)
    private int kind;
}
