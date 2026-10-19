package com.example.netproto.spring.configtest;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;

/** 自动装配测试夹具:挂在 UDP 7777 的用户协议(无 Lombok,starter 模块保持零额外依赖)。 */
@Protocol(id = "probe-a", name = "Probe A")
@BindOn(parent = "udp", when = "dstPort == 7777 || srcPort == 7777")
public class ProbeA {

    @ProtocolField(order = 1, size = 8)
    private int kind;

    public int getKind() {
        return kind;
    }

    public void setKind(int kind) {
        this.kind = kind;
    }
}
