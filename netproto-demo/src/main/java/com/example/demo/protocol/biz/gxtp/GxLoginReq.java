package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.nio.charset.StandardCharsets;

/**
 * GXTP 登录请求(msgType=1)。
 * 演示机制:lengthField 变长 STRING、presentIf 条件字段组
 * (hasToken==1 时 tokenLen/token 才存在)、sentinel 零终止字符串(remark)。
 */
@Data
@ToString
@Protocol(id = "gx-login", name = "GXTP Login 请求")
@BindOn(parent = "gxtp", when = "msgType == 1")
public class GxLoginReq {

    @ProtocolField(order = 1, size = 8)
    private int userLen;

    @ProtocolField(order = 2, type = FieldType.STRING, lengthField = "userLen")
    private String username = "";

    /** 1=携带 token 字段组。 */
    @ProtocolField(order = 3, size = 8)
    private int hasToken;

    @ProtocolField(order = 4, size = 16, presentIf = "hasToken == 1")
    private int tokenLen;

    @ProtocolField(order = 5, type = FieldType.BYTES,
            lengthField = "tokenLen", presentIf = "hasToken == 1")
    private byte[] token = new byte[0];

    /** C 风格零终止备注(读到 0x00 为止)。 */
    @ProtocolField(order = 6, type = FieldType.STRING, sentinel = 0)
    private String remark = "";

    public static GxLoginReq of(String username, byte[] token, String remark) {
        GxLoginReq r = new GxLoginReq();
        r.setUsername(username);
        r.setUserLen(username.getBytes(StandardCharsets.UTF_8).length);
        if (token != null && token.length > 0) {
            r.setHasToken(1);
            r.setToken(token);
            r.setTokenLen(token.length);
        }
        r.setRemark(remark == null ? "" : remark);
        return r;
    }
}
