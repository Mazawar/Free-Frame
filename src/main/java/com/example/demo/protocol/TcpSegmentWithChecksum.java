package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ChecksumField;
import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.Checksum;
import lombok.Data;
import lombok.ToString;

import java.io.ByteArrayOutputStream;

/**
 * TCP 段(带校验和钩子,含伪首部)。checksum 字段序列化时由引擎置0→算→回写。
 * 伪首部(源IP/目的IP/协议)存在 transient 字段,用户装配时填。
 * 算法:伪首部(12B) + serialized(TCP头) 反码求和取反。
 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class TcpSegmentWithChecksum implements Checksum {

    @ProtocolField(order = 1, size = 16) private int srcPort;
    @ProtocolField(order = 2, size = 16) private int dstPort;
    @ProtocolField(order = 3, size = 32) private long seqNumber;
    @ProtocolField(order = 4, size = 32) private long ackNumber;
    @ProtocolField(order = 5, size = 4)  private int dataOffset;
    @ProtocolField(order = 6, size = 6)  private int reserved;
    @ProtocolField(order = 7, size = 6)  private int flags;
    @ProtocolField(order = 8, size = 16) private int window;
    @ProtocolField(order = 9, size = 16)
    @ChecksumField
    private int checksum;
    @ProtocolField(order = 10, size = 16) private int urgentPointer;

    private transient int pseudoSourceIp;
    private transient int pseudoDestIp;
    private transient int pseudoProtocol;

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"checksum".equals(field)) {
            return -1;
        }
        byte[] pseudo = buildPseudoHeader(serialized.length);
        byte[] full = concat(pseudo, serialized);
        return onesComplementSum(full);
    }

    private byte[] buildPseudoHeader(int tcpLength) {
        byte[] p = new byte[12];
        p[0] = (byte) (pseudoSourceIp >>> 24);
        p[1] = (byte) (pseudoSourceIp >>> 16);
        p[2] = (byte) (pseudoSourceIp >>> 8);
        p[3] = (byte) pseudoSourceIp;
        p[4] = (byte) (pseudoDestIp >>> 24);
        p[5] = (byte) (pseudoDestIp >>> 16);
        p[6] = (byte) (pseudoDestIp >>> 8);
        p[7] = (byte) pseudoDestIp;
        p[8] = 0;
        p[9] = (byte) pseudoProtocol;
        p[10] = (byte) (tcpLength >>> 8);
        p[11] = (byte) tcpLength;
        return p;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(a.length + b.length);
        bos.writeBytes(a);
        bos.writeBytes(b);
        return bos.toByteArray();
    }

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
