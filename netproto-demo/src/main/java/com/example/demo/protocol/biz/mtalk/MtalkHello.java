package com.example.demo.protocol.biz.mtalk;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * MTALK 握手(cmd=0x10):定长协议名 + 变长 nonce。
 * 演示机制:定长 STRING(size=40,5 字节 "MTALK")、lengthField 变长 BYTES 组合。
 */
@Data
@ToString
@Protocol(id = "mtalk-hello", name = "MTALK 握手")
@BindOn(parent = "mtalk", when = "cmd == 0x10")
public class MtalkHello {

    @ProtocolField(order = 1, type = FieldType.STRING, size = 40)
    private String protoName = "MTALK";

    @ProtocolField(order = 2, size = 8)
    private int nonceLen;

    @ProtocolField(order = 3, type = FieldType.BYTES, lengthField = "nonceLen")
    private byte[] nonce = new byte[0];

    public static MtalkHello of(byte[] nonce) {
        MtalkHello h = new MtalkHello();
        h.setNonce(nonce);
        h.setNonceLen(nonce.length);
        return h;
    }
}
