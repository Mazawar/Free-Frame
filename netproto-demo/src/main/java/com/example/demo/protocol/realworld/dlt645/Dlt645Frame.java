package com.example.demo.protocol.realworld.dlt645;

import com.example.netproto.annotation.ChecksumField;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.Checksum;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * DL/T 645-2007 多功能电能表通信规约(中国电表事实标准)——串口帧,孤岛协议。
 * <pre>
 *  | 68H | 地址(6B,BCD 低位在前) | 68H | 控制码(8b) | 长度L(8b) | 数据域(L 字节) | CS(8b) | 16H |
 *    控制码: D7 方向 D6 从站异常 D5 后续帧 D4-D0 功能码
 *    CS = 从首个 68H 到数据域最后一字节的模 256 累加和
 * </pre>
 * 验证点:定界符常量字段、控制码 1+1+1+5 位拆分、lengthField+lengthAdjust
 * (L 含 DI 4 字节,数据体 = L-4)、@ChecksumField 模 256 累加和。
 * 子集:读数据响应(控制码 0x91:方向=1 功能=0x11,数据域 = DI0-DI3 + 数据)。
 */
@Data
@ToString
@Protocol(id = "dlt645", name = "DL/T 645 电表")
public class Dlt645Frame implements Checksum {

    @ProtocolField(order = 1, size = 8)
    private int start1 = 0x68;

    /** 表地址 6 字节(BCD 低位在前,按原始字节展示)。 */
    @ProtocolField(order = 2, type = FieldType.BYTES, size = 48)
    private byte[] address = new byte[6];

    @ProtocolField(order = 3, size = 8)
    private int start2 = 0x68;

    /** D7 主站(0)/从站(1)。 */
    @ProtocolField(order = 4, size = 1)
    private int dirBit;

    /** D6 从站异常应答标志。 */
    @ProtocolField(order = 5, size = 1)
    private int errBit;

    /** D5 后续帧标志。 */
    @ProtocolField(order = 6, size = 1)
    private int followBit;

    /** D4-D0 功能码(0x11=读数据)。 */
    @ProtocolField(order = 7, size = 5)
    private int funcCode;

    /** 数据域长度 L(含 DI 4 字节)。 */
    @ProtocolField(order = 8, size = 8)
    private int dataLen;

    /** 数据标识 DI0-DI3(读数据响应必有)。 */
    @ProtocolField(order = 9, size = 32, presentIf = "funcCode == 17 && dirBit == 1")
    private long dataId;

    /** 数据体 = L - 4(lengthAdjust 负偏移)。 */
    @ProtocolField(order = 10, type = FieldType.BYTES,
            lengthField = "dataLen", lengthAdjust = -4,
            presentIf = "funcCode == 17 && dirBit == 1")
    private byte[] data = new byte[0];

    @ProtocolField(order = 11, size = 8)
    @ChecksumField
    private int cs;

    @ProtocolField(order = 12, size = 8)
    private int end = 0x16;

    /** 组装便捷工厂:读数据响应(DI + 数据体)。 */
    public static Dlt645Frame readResp(byte[] address, long dataId, byte[] data) {
        Dlt645Frame f = new Dlt645Frame();
        f.setAddress(address);
        f.setDirBit(1);
        f.setFuncCode(0x11);
        f.setDataId(dataId);
        f.setData(data);
        f.setDataLen(4 + data.length);
        return f;
    }

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"cs".equals(field)) {
            return -1;
        }
        // 规约:CS = 首个 68H 到数据域末字节的累加和 mod 256 —— 不含结尾 16H,
        // 故去掉 serialized 最后一字节(结束符位置);CS 自身位置已被引擎置 0。
        int sum = 0;
        for (int i = 0; i < serialized.length - 1; i++) {
            sum += serialized[i] & 0xFF;
        }
        return sum & 0xFF;
    }
}
