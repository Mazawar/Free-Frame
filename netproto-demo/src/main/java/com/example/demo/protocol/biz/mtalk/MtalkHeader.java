package com.example.demo.protocol.biz.mtalk;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * 私有协议形态三:TCP 8899 承载的消息协议 —— 同端口、公共头部、cmd 字段分派。
 * <pre>
 *  0        1        2                   6
 *  +--------+--------+-------------------+
 *  |  cmd   | status |   sessionKey(32b) |
 *  +--------+--------+-------------------+
 *  | cmd=0x10 → MtalkHello   cmd=0x20 → MtalkEventBatch |
 *  +-----------------------------------------------------+
 * </pre>
 * 演示机制:TCP 端口分派 + cmd 字段分派(与 UDP 侧同构,验证两种传输层接法)。
 */
@Data
@ToString
@Protocol(id = "mtalk", name = "MTALK 消息协议")
@BindOn(parent = "tcp", when = "dstPort == 8899 || srcPort == 8899")
public class MtalkHeader {

    /** 命令字:子协议分派字段(0x10=握手 0x20=事件批量上报)。 */
    @ProtocolField(order = 1, size = 8)
    private int cmd;

    @ProtocolField(order = 2, size = 8)
    private int status;

    @ProtocolField(order = 3, size = 32, type = FieldType.UNSIGNED)
    private long sessionKey;

    public static MtalkHeader of(int cmd, int status, long sessionKey) {
        MtalkHeader h = new MtalkHeader();
        h.setCmd(cmd);
        h.setStatus(status);
        h.setSessionKey(sessionKey);
        return h;
    }
}
