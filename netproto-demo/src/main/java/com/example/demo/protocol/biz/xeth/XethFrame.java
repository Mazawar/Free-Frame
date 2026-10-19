package com.example.demo.protocol.biz.xeth;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * 私有协议形态一:直挂以太网(本地实验 EtherType 0x88B5,IEEE 划给私有协议的范围)。
 * <p>
 * 公共头部 + channel 字段分派子协议 —— 典型工控/车载总线风格:
 * <pre>
 *  0                   1                   2                   3
 *  +-------+-----------+---------+------------------------------+
 *  |ver(4b)|busFlags(4)| channel |        seq (16b)             |
 *  +-------+-----------+---------+------------------------------+
 *  |optCount|  XethOption × optCount (countField 驱动嵌套列表)   |
 *  +--------+-------------------------------------------------+
 *  | channel==1 → XethTelemetry   channel==2 → XethAlarm        |
 *  +------------------------------------------------------------+
 * </pre>
 * 演示机制:EtherType 分派、4bit 位拆分、countField 嵌套对象列表、
 * 头部列表之后的「按字段再分派」两级下降。
 */
@Data
@ToString
@Protocol(id = "xeth", name = "XETH 私有总线")
@BindOn(parent = "ethernet", when = "etherType == 0x88B5")
public class XethFrame {

    @ProtocolField(order = 1, size = 4)
    private int version = 1;

    /** 总线状态位:bit0 时钟同步 / bit1 冗余链路。 */
    @ProtocolField(order = 2, size = 4)
    private int busFlags;

    /** 载荷通道:子协议分派字段(1=遥测 2=告警)。 */
    @ProtocolField(order = 3, size = 8)
    private int channel;

    @ProtocolField(order = 4, size = 16, type = FieldType.UNSIGNED)
    private int seq;

    @ProtocolField(order = 5, size = 8)
    private int optCount;

    @ProtocolField(order = 6, type = FieldType.LIST,
            countField = "optCount", elementClass = XethOption.class)
    private List<XethOption> options = new ArrayList<>();

    public static XethFrame of(int channel, int seq, List<XethOption> options) {
        XethFrame f = new XethFrame();
        f.setChannel(channel);
        f.setSeq(seq);
        f.setOptions(new ArrayList<>(options));
        f.setOptCount(options.size());
        return f;
    }
}
