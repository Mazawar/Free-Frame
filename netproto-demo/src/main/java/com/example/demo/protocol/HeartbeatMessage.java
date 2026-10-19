package com.example.demo.protocol;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.VarintCodec;
import lombok.Data;
import lombok.ToString;

/**
 * L2 逃生舱示例协议:uptime 用自定义 varint 编解码(LEB128),
 * hostname 为 C 风格零终止字符串 —— 两种「怪字段」零手写协议级代码接入。
 * 挂在 UDP 9998,与 my-app(9999)并列为分派树的业务叶子。
 */
@Data
@ToString
@Protocol(id = "heartbeat", name = "Heartbeat (demo)")
@BindOn(parent = "udp", when = "dstPort == 9998 || srcPort == 9998")
public class HeartbeatMessage {

    @ProtocolField(order = 1, size = 8)
    private int deviceType;

    /** varint(LEB128):1–10 字节自适应。 */
    @ProtocolField(order = 2, custom = VarintCodec.class)
    private Long uptimeMs;

    /** C 风格零终止字符串(sentinel 驱动)。 */
    @ProtocolField(order = 3, sentinel = 0, charset = "UTF-8")
    private String hostname;
}
