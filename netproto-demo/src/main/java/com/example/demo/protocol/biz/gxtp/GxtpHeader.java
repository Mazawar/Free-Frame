package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.Set;

/**
 * 私有协议形态二:UDP 7788 承载的网关传输协议 —— 「同一个端口进来、
 * 公共头部之后按 msgType 字段分派到不同报文体」,业务系统最常见的私有协议形态。
 * <pre>
 *  0        1        2        3        4                  8
 *  +--------+--------+--------+--------+------------------+
 *  | magic  | ver    | msgType| flags  |     reqId (32b)  |
 *  +--------+--------+--------+--------+------------------+
 *  | msgType=1 → GxLoginReq    msgType=2 → GxTelemetryReport|
 *  | msgType=3 → GxConfigBody  msgType=4 → GxFileChunk      |
 *  +-------------------------------------------------------+
 * </pre>
 * 演示机制:端口分派、flagClass 位标志集合、按字段分派四种报文体。
 */
@Data
@ToString
@Protocol(id = "gxtp", name = "GXTP 网关传输协议")
@BindOn(parent = "udp", when = "dstPort == 7788 || srcPort == 7788")
public class GxtpHeader {

    /** 固定签名 0x4758('GX')。 */
    @ProtocolField(order = 1, size = 16)
    private int magic = 0x4758;

    @ProtocolField(order = 2, size = 8)
    private int version = 2;

    /** 报文体类型:子协议分派字段。 */
    @ProtocolField(order = 3, size = 8)
    private int msgType;

    @ProtocolField(order = 4, size = 8, flagClass = GxtpFlag.class)
    private Set<GxtpFlag> flags = new java.util.HashSet<>();

    @ProtocolField(order = 5, size = 32, type = FieldType.UNSIGNED)
    private long reqId;

    public static GxtpHeader of(int msgType, long reqId, GxtpFlag... flags) {
        GxtpHeader h = new GxtpHeader();
        h.setMsgType(msgType);
        h.setReqId(reqId);
        for (GxtpFlag f : flags) {
            h.getFlags().add(f);
        }
        return h;
    }
}
