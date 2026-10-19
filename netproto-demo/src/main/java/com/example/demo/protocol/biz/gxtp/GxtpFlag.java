package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.core.ProtocolFlag;

/** GXTP 标志位(头部 flags 字段位掩码)。 */
public enum GxtpFlag implements ProtocolFlag {
    COMPRESSED(0x01),
    ENCRYPTED(0x02),
    ACK_REQ(0x04),
    RETRANSMIT(0x08);

    private final int m;

    GxtpFlag(int m) {
        this.m = m;
    }

    @Override
    public int mask() {
        return m;
    }
}
