package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ChecksumField;
import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.Checksum;
import lombok.Data;
import lombok.ToString;

/**
 * IPv4 头(带校验和钩子)。headerChecksum 字段序列化时由引擎置0→算→回写。
 * 反码求和算法由本实体实现(compute)。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class Ipv4HeaderWithChecksum implements Checksum {

    @ProtocolField(order = 1, size = 4)   private int version;
    @ProtocolField(order = 2, size = 4)   private int ihl;
    @ProtocolField(order = 3, size = 8)   private int tos;
    @ProtocolField(order = 4, size = 16)  private int totalLength;
    @ProtocolField(order = 5, size = 16)  private int identification;
    @ProtocolField(order = 6, size = 3)   private int flags;
    @ProtocolField(order = 7, size = 13)  private int fragmentOffset;
    @ProtocolField(order = 8, size = 8)   private int ttl;
    @ProtocolField(order = 9, size = 8)   private int protocol;
    @ProtocolField(order = 10, size = 16)
    @ChecksumField
    private int headerChecksum;
    @ProtocolField(order = 11, size = 32) private int sourceIp;
    @ProtocolField(order = 12, size = 32) private int destinationIp;

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"headerChecksum".equals(field)) {
            return -1;  // 不接管
        }
        return onesComplementSum(serialized);
    }

    /** IPv4 16 位反码求和。serialized 里校验和字段已被引擎置 0。 */
    private static long onesComplementSum(byte[] data) {
        long sum = 0;
        for (int i = 0; i + 1 < data.length; i += 2) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
        }
        if ((data.length & 1) != 0) {
            sum += (data[data.length - 1] & 0xFF) << 8;
        }
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (~sum) & 0xFFFF;
    }
}
