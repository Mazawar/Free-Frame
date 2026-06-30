package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolEnum;

/** IP 协议号(RFC 790 子集)。值 = 协议在 IP 头里的 wire 值。 */
public enum IpProtocol implements ProtocolEnum {
    ICMP(1),
    TCP(6),
    UDP(17);

    private final int v;

    IpProtocol(int v) {
        this.v = v;
    }

    @Override
    public int value() {
        return v;
    }
}
