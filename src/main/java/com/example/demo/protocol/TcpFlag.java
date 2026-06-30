package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolFlag;

/** TCP 标志位(RFC 793)。mask = 该 flag 在 flags 字段中的位掩码。 */
public enum TcpFlag implements ProtocolFlag {
    FIN(0x01),
    SYN(0x02),
    RST(0x04),
    PSH(0x08),
    ACK(0x10),
    URG(0x20);

    private final int m;

    TcpFlag(int m) {
        this.m = m;
    }

    @Override
    public int mask() {
        return m;
    }
}
