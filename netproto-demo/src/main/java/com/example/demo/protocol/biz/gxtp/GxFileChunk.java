package com.example.demo.protocol.biz.gxtp;

import com.example.netproto.annotation.BindOn;
import com.example.netproto.annotation.ChecksumField;
import com.example.netproto.annotation.Protocol;
import com.example.netproto.annotation.ProtocolField;
import com.example.netproto.core.Checksum;
import com.example.netproto.core.FieldType;
import lombok.Data;
import lombok.ToString;

/**
 * GXTP 文件分片(msgType=4):固件/日志类大块数据传输。
 * 演示机制:lengthField 变长 BYTES + @ChecksumField 序列化期校验和回写
 * (引擎把 crc16 置 0 → 调 compute → 回写;算法 CRC-16/CCITT-FALSE)。
 */
@Data
@ToString
@Protocol(id = "gx-file", name = "GXTP 文件分片")
@BindOn(parent = "gxtp", when = "msgType == 4")
public class GxFileChunk implements Checksum {

    @ProtocolField(order = 1, size = 16)
    private int fileId;

    @ProtocolField(order = 2, size = 32, type = FieldType.UNSIGNED)
    private long chunkIdx;

    @ProtocolField(order = 3, size = 32, type = FieldType.UNSIGNED)
    private long totalChunks;

    @ProtocolField(order = 4, size = 16)
    private int dataLen;

    @ProtocolField(order = 5, type = FieldType.BYTES, lengthField = "dataLen")
    private byte[] data = new byte[0];

    @ProtocolField(order = 6, size = 16)
    @ChecksumField
    private int crc16;

    public static GxFileChunk of(int fileId, long chunkIdx, long totalChunks, byte[] data) {
        GxFileChunk c = new GxFileChunk();
        c.setFileId(fileId);
        c.setChunkIdx(chunkIdx);
        c.setTotalChunks(totalChunks);
        c.setData(data);
        c.setDataLen(data.length);
        return c;
    }

    @Override
    public long compute(String field, byte[] serialized) {
        if (!"crc16".equals(field)) {
            return -1;
        }
        return crc16CcittFalse(serialized);
    }

    /** CRC-16/CCITT-FALSE:poly=0x1021, init=0xFFFF。 */
    public static int crc16CcittFalse(byte[] data) {
        int crc = 0xFFFF;
        for (byte b : data) {
            crc ^= (b & 0xFF) << 8;
            for (int i = 0; i < 8; i++) {
                crc = ((crc & 0x8000) != 0) ? ((crc << 1) ^ 0x1021) : (crc << 1);
                crc &= 0xFFFF;
            }
        }
        return crc;
    }
}
