package com.example.netproto.protocols.builtin;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.ChecksumField;
import com.example.netproto.annotation.Payload;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.Checksum;
import com.example.netproto.core.PayloadAware;
import lombok.Data;
import lombok.ToString;

import java.util.Arrays;

/**
 * IPv4 包(RFC 791,无选项,IHL=5)。
 * <ul>
 *   <li>校验和:头部 20 字节反码求和(序列化时引擎置 0 → compute → 回写);</li>
 *   <li>totalLength:组装期由 {@link #onPayload} 按 payload 尺寸自动填写;</li>
 *   <li>protocol 由 StackEncoder 按子协议绑定的 when 自动接线。</li>
 * </ul>
 */
@Data
@ToString
@Protocol(id = "ipv4", name = "IPv4", builtin = true)
@BindOn(parent = "ethernet", when = "etherType == 0x0800")
public class Ipv4Packet implements Checksum, PayloadAware {

    @ProtocolField(order = 1, size = 4)
    private int version = 4;

    @ProtocolField(order = 2, size = 4)
    private int ihl = 5;

    @ProtocolField(order = 3, size = 8)
    private int tos;

    @ProtocolField(order = 4, size = 16)
    private int totalLength;

    @ProtocolField(order = 5, size = 16)
    private int identification;

    @ProtocolField(order = 6, size = 3)
    private int flags;

    @ProtocolField(order = 7, size = 13)
    private int fragmentOffset;

    @ProtocolField(order = 8, size = 8)
    private int ttl = 64;

    @ProtocolField(order = 9, size = 8)
    private int protocol;

    @ProtocolField(order = 10, size = 16)
    @ChecksumField
    private int headerChecksum;

    @ProtocolField(order = 11, size = 32)
    private int sourceIp;

    @ProtocolField(order = 12, size = 32)
    private int destinationIp;

    @Payload
    private byte[] payload;

    @Override
    public void onPayload(byte[] innerPayload) {
        this.version = 4;
        this.ihl = 5;
        this.totalLength = ihl * 4 + innerPayload.length;
    }

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"headerChecksum".equals(field)) {
            return -1;
        }
        // 校验和只覆盖头部(serialized 含 payload,须按 IHL 切片)
        int headerLen = Math.min(serialized.length, (serialized[0] & 0x0F) * 4);
        return onesComplementSum(Arrays.copyOfRange(serialized, 0, headerLen));
    }

    /** 16 位反码求和(头部字节,校验和字段已被引擎置 0)。 */
    static long onesComplementSum(byte[] data) {
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
