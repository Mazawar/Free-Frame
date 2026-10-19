package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/** 配置项·原始字节(TLV type=3):密钥/证书等二进制配置。 */
@Data
@ToString
@Protocol(id = "gx-conf-blob", name = "GXTP 配置·字节")
public class GxConfBlob {

    @ProtocolField(order = 1, size = 16)
    private int confId;

    @ProtocolField(order = 2, size = 8)
    private int blobLen;

    @ProtocolField(order = 3, type = FieldType.BYTES, lengthField = "blobLen")
    private byte[] blob = new byte[0];

    public static GxConfBlob of(int confId, byte[] blob) {
        GxConfBlob b = new GxConfBlob();
        b.setConfId(confId);
        b.setBlob(blob);
        b.setBlobLen(blob.length);
        return b;
    }
}
