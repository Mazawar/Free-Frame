package com.netproto.demo.protocol.iot;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * 物联网系统 水利设备公共头(UDP 9002 承载)。
 * <pre>
 * | 源地址(3B) | 帧类型(1B) | 源IP(4B) | 源端口(2B) | 源GPS(4B) | token(2B) | 信令体... |
 * 帧类型 = 分派选择子(01 设备配置 / 02 设备配置响应);XML 未给出取值,演示约定 01/02。
 * </pre>
 */
@Data
@ToString
@Protocol(id = "iot", name = "水利设备接入", group = "物联网", internal = true)
@BindOn(parent = "udp", when = "dstPort == 9002 || srcPort == 9002")
public class IotFrame implements PayloadAware {

    @ProtocolField(order = 1, size = 24, label = "源地址")
    private int srcAddr = 1;

    /** 分派选择子:01 设备配置 / 02 设备配置响应(编码期自动接线)。 */
    @ProtocolField(order = 2, size = 8, label = "帧类型")
    private int frameType = 1;

    @ProtocolField(order = 3, size = 32, label = "源IP")
    private int srcIp = 0xC0A80164;          // 192.168.1.100

    @ProtocolField(order = 4, size = 16, label = "源端口")
    private int srcPort = 51888;

    /** 定点经纬度打包值(4B 占位)。 */
    @ProtocolField(order = 5, size = 32, label = "源GPS")
    private int gps;

    @ProtocolField(order = 6, size = 16, label = "token")
    private int token;

    @Payload
    private byte[] body = new byte[0];

    @Override
    public void onPayload(byte[] inner) {
        // 无长度字段:UDP 数据报天然定界
    }
}
