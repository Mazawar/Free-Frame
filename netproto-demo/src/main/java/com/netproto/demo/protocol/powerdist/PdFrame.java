package com.netproto.demo.protocol.powerdist;

import com.netproto.annotation.BindOn;
import com.netproto.annotation.Payload;
import com.netproto.annotation.Protocol;
import com.netproto.annotation.ProtocolField;
import com.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

/**
 * 智能配电接入协议 公共头(UDP 9000 承载)。
 * <pre>
 * | 版本号(1B)=0x21 | 信令类型(1B) | 源地址(4B) | 目标地址(4B)
 * | 流水号(2B) | 认证令牌(2B) | 报文长度(2B) | 信令体... |
 *
 * 报文长度 = 整帧字节数(含 16B 头),组装期由 onPayload 自动回填;
 * 信令类型 = 子协议分派选择子(01x 注册类 / 11x 参数类 / 21x 上报类,见各子协议 @BindOn),
 * 编码时选择子自动接线:内层协议的绑定条件反推本字段,无需手工填。
 * </pre>
 * 字段默认值即页面发包表单默认值(源=1 号终端,目标=平台,令牌未注册全 0)。
 */
@Data
@ToString
@Protocol(id = "pd", name = "智能配电接入", group = "智能配电")
@BindOn(parent = "udp", when = "dstPort == 9000 || srcPort == 9000")
public class PdFrame implements PayloadAware {

    @ProtocolField(order = 1, size = 8, label = "版本号")
    private int version = 0x21;

    /** 信令类型:子协议分派字段(编码期按内层协议自动接线)。 */
    @ProtocolField(order = 2, size = 8, label = "信令类型")
    private int signalType;

    /** 1 = 一号配电终端。 */
    @ProtocolField(order = 3, size = 32, label = "源地址")
    private int srcAddr = 1;

    /** 0 = 服务平台。 */
    @ProtocolField(order = 4, size = 32, label = "目标地址")
    private int dstAddr;

    @ProtocolField(order = 5, size = 16, label = "流水号")
    private int seqNo = 1;

    /** 注册前全 0;注册许可(0x02)后携带平台分配的令牌。 */
    @ProtocolField(order = 6, size = 16, label = "认证令牌")
    private int token;

    /** 整帧长度(含本头 16B),组装期自动。 */
    @ProtocolField(order = 7, size = 16, label = "报文长度")
    private int frameLength;

    /** 信令体:整帧剩余字节(UDP 数据报天然定界,解码取到本层末尾)。 */
    @Payload
    private byte[] body = new byte[0];

    @Override
    public void onPayload(byte[] inner) {
        this.frameLength = 16 + inner.length;
    }
}
