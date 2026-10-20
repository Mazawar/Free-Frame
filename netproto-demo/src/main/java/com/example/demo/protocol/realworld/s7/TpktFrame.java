package com.example.demo.protocol.realworld.s7;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * TPKT(RFC 1006,西门子 S7comm 底层,TCP 102):4 字节定长头。
 * <pre>
 *  | version(8b)=3 | reserved(8b)=0 | length(16b,含 4B 头本身) |
 * </pre>
 * 验证点:多级定长头的第一级;length 含头自身(onPayload 钩子回填)。
 */
@Data
@ToString
@Protocol(id = "tpkt", name = "TPKT", group = "S7comm")
@BindOn(parent = "tcp", when = "dstPort == 102 || srcPort == 102")
public class TpktFrame implements PayloadAware {

    @ProtocolField(order = 1, size = 8)
    private int version = 3;

    @ProtocolField(order = 2, size = 8)
    private int reserved;

    /** 总长度,含本头 4 字节。 */
    @ProtocolField(order = 3, size = 16)
    private int length;

    @Override
    public void onPayload(byte[] inner) {
        this.length = 4 + inner.length;
    }
}
