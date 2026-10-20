package com.netproto.core;

/**
 * LEB128 varint 字段编解码(L2 逃生舱示例,protobuf wire format 同款):
 * 每字节低 7 位是数据,最高位为继续标志。
 */
public class VarintCodec implements FieldCodec<Long> {

    @Override
    public Long read(BitCursor cursor, FieldContext ctx, int remainingBytes) {
        long result = 0;
        int shift = 0;
        while (true) {
            int b = (int) cursor.readBits(8) & 0xFF;
            result |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
            shift += 7;
            if (shift >= 64) {
                throw new IllegalStateException("varint too long (>64 bits)");
            }
        }
    }

    @Override
    public void write(BitCursor cursor, FieldContext ctx, Long value) {
        long v = value == null ? 0 : value;
        do {
            int b = (int) (v & 0x7F);
            v >>>= 7;
            if (v != 0) {
                b |= 0x80;
            }
            cursor.writeBits(b, 8);
        } while (v != 0);
    }

    @Override
    public long sizeOf(Long value) {
        long v = value == null ? 0 : value;
        int bytes = 1;
        while ((v >>>= 7) != 0) {
            bytes++;
        }
        return bytes * 8L;
    }
}
