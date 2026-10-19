package com.example.demo.protocol.biz.xeth;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * XETH 告警报文(channel=2):hasDetail==1 时 detailLen/detail 才存在。
 * 演示机制:presentIf 条件字段(两个联动字段同条件缺席)、变长 STRING(lengthField)。
 */
@Data
@ToString
@Protocol(id = "xeth-alarm", name = "XETH 告警")
@BindOn(parent = "xeth", when = "channel == 2")
public class XethAlarm {

    /** 0=INFO 1=WARN 2=CRIT。 */
    @ProtocolField(order = 1, size = 8)
    private int severity;

    @ProtocolField(order = 2, size = 16)
    private int alarmCode;

    @ProtocolField(order = 3, size = 8)
    private int hasDetail;

    @ProtocolField(order = 4, size = 16, presentIf = "hasDetail == 1")
    private int detailLen;

    @ProtocolField(order = 5, type = FieldType.STRING,
            lengthField = "detailLen", presentIf = "hasDetail == 1")
    private String detail = "";

    public static XethAlarm of(int severity, int alarmCode, String detail) {
        XethAlarm a = new XethAlarm();
        a.setSeverity(severity);
        a.setAlarmCode(alarmCode);
        if (detail != null && !detail.isEmpty()) {
            a.setHasDetail(1);
            a.setDetail(detail);
            a.setDetailLen(detail.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
        }
        return a;
    }
}
