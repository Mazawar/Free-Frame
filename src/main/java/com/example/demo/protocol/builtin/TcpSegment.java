package com.example.demo.protocol.builtin;

import com.example.demo.protocol.TcpFlag;
import com.example.demo.protocol.annotation.BindOn;
import com.example.demo.protocol.annotation.Payload;
import com.example.demo.protocol.annotation.Protocol;
import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

import java.util.Set;

/**
 * TCP 段(RFC 793,固定 20 字节头,无选项):dataOffset 组装期自动 = 5。
 * <p>
 * 边界:checksum 置 0(伪头跨层,同 UDP);raw 注入的 TCP 无内核栈握手,
 * 仅适合演示/测试场景(见设计文档)。
 */
@Data
@ToString
@Protocol(id = "tcp", name = "TCP", builtin = true)
@BindOn(parent = "ipv4", when = "protocol == 6")
public class TcpSegment implements PayloadAware {

    @ProtocolField(order = 1, size = 16)
    private int srcPort;

    @ProtocolField(order = 2, size = 16)
    private int dstPort;

    @ProtocolField(order = 3, size = 32)
    private long sequenceNumber;

    @ProtocolField(order = 4, size = 32)
    private long acknowledgmentNumber;

    /** 数据偏移(单位 4 字节,无选项 = 5)。 */
    @ProtocolField(order = 5, size = 4)
    private int dataOffset = 5;

    @ProtocolField(order = 6, size = 4)
    private int reserved;

    @ProtocolField(order = 7, size = 8, flagClass = TcpFlag.class)
    private Set<TcpFlag> flags;

    @ProtocolField(order = 8, size = 16)
    private int window = 8192;

    /** 0 = 未计算(伪头跨层边界,见设计文档)。 */
    @ProtocolField(order = 9, size = 16)
    private int checksum;

    @ProtocolField(order = 10, size = 16)
    private int urgentPointer;

    @Payload
    private byte[] payload;

    @Override
    public void onPayload(byte[] innerPayload) {
        this.dataOffset = 5;
        this.checksum = 0;
    }
}
