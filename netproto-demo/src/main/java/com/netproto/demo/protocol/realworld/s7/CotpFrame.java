package com.netproto.demo.protocol.realworld.s7;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * COTP DT 数据 TPDU(RFC 905 / ISO 8073):3 字节定长头(S7 走到的分支)。
 * <pre>
 *  | LI(8b)=2 | pduType(8b)=0xF0(DT) | tpduNumber(8b)=0x80(最后一个片段) |
 * </pre>
 * 验证点:父层无「业务分派字段」时用协议常量字段(version==3 / pduType==0xF0)作绑定条件。
 */
@Data
@ToString
@Protocol(id = "cotp", name = "COTP", group = "S7comm")
@BindOn(parent = "tpkt", when = "version == 3")
public class CotpFrame implements PayloadAware {

    /** 长度指示器:本 TPDU 头中 LI 之后的字节数(DT 固定 = 2)。 */
    @ProtocolField(order = 1, size = 8)
    private int lengthIndicator = 2;

    /** 0xF0 = DT 数据 TPDU:子层分派字段。 */
    @ProtocolField(order = 2, size = 8)
    private int pduType = 0xF0;

    /** 0x80 = EOT,最后一个片段。 */
    @ProtocolField(order = 3, size = 8)
    private int tpduNumber = 0x80;

    @Override
    public void onPayload(byte[] inner) {
        this.lengthIndicator = 2;
    }
}
