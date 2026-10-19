package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.nio.charset.StandardCharsets;

/** 配置项·文本(TLV type=2):confId + textLen + UTF-8 文本。 */
@Data
@ToString
@Protocol(id = "gx-conf-string", name = "GXTP 配置·文本")
public class GxConfString {

    @ProtocolField(order = 1, size = 16)
    private int confId;

    @ProtocolField(order = 2, size = 8)
    private int textLen;

    @ProtocolField(order = 3, type = FieldType.STRING, lengthField = "textLen")
    private String text = "";

    public static GxConfString of(int confId, String text) {
        GxConfString s = new GxConfString();
        s.setConfId(confId);
        s.setText(text);
        s.setTextLen(text.getBytes(StandardCharsets.UTF_8).length);
        return s;
    }
}
