package com.netproto.demo.protocol.devcomm;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * 设备通信协议 公共头(UDP 9001 承载)。
 * <pre>
 * | 源设备编号(3B) | 目标设备编号(3B) | 信令类型(1B) | 信令体... |
 * 信令类型在 XML 里逐信令声明,线路上紧跟公共头,此处归入头作为分派选择子;
 * 安全信息(4B)在各信令体内,注册响应后由平台分配。
 * </pre>
 */
@Data
@ToString
@Protocol(id = "dev", name = "设备通信", group = "设备通信")
@BindOn(parent = "udp", when = "dstPort == 9001 || srcPort == 9001")
public class DevFrame implements PayloadAware {

    /** 000000 服务端 / 000001 终端A / 000002 终端B。 */
    @ProtocolField(order = 1, size = 24, label = "源设备编号")
    private int srcDev = 1;

    @ProtocolField(order = 2, size = 24, label = "目标设备编号")
    private int dstDev;

    /** 信令类型:分派选择子(编码期按内层协议自动接线)。 */
    @ProtocolField(order = 3, size = 8, label = "信令类型")
    private int signalType;

    @Payload
    private byte[] body = new byte[0];

    @Override
    public void onPayload(byte[] inner) {
        // 无长度字段:UDP 数据报天然定界
    }
}
