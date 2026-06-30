package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.DynamicSize;
import com.example.demo.protocol.core.FieldContext;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * IPv4 头(20 字节固定 + 可变 options)。options 长度由 (IHL-5)*4 字节决定,用钩子算。
 * Phase 1:headerChecksum 当普通字段(Phase 3 接校验和钩子)。
 * flags 按 reserved/df/mf 顺序组合为 3 位。fragmentOffset 13 位。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class Ipv4Header implements DynamicSize {

    @ProtocolField(order = 1, size = 4)   private int version;
    @ProtocolField(order = 2, size = 4)   private int ihl;          // 32-bit words
    @ProtocolField(order = 3, size = 8)   private int tos;          // 1.8.2 整体 8 bit(无 DSCP/ECN)
    @ProtocolField(order = 4, size = 16)  private int totalLength;
    @ProtocolField(order = 5, size = 16)  private int identification;
    @ProtocolField(order = 6, size = 3)   private int flags;        // reserved/df/mf
    @ProtocolField(order = 7, size = 13)  private int fragmentOffset;
    @ProtocolField(order = 8, size = 8)   private int ttl;
    @ProtocolField(order = 9, size = 8)   private int protocol;
    @ProtocolField(order = 10, size = 16) private int headerChecksum;
    @ProtocolField(order = 11, size = 32) private int sourceIp;
    @ProtocolField(order = 12, size = 32) private int destinationIp;
    @ProtocolField(order = 13, type = FieldType.BYTES) private byte[] options;

    public Ipv4Header() {
        this.options = new byte[0];
    }

    @Override
    public long computeSize(String field, FieldContext ctx) {
        if ("options".equals(field)) {
            long headerBytes = ctx.getInt("ihl") * 4L; // IHL 单位是 32-bit word
            long optionBytes = headerBytes - 20;       // 固定部分 20 字节
            return Math.max(0, optionBytes) * 8;       // bit
        }
        return -1; // 其余字段走声明式 size
    }
}
