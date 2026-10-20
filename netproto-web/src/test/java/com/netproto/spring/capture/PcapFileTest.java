package com.netproto.spring.capture;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** pcap 读写:回环一致、四种魔数(Wireshark/tcpdump 写出的端序×精度组合)、非法输入明确报错。 */
class PcapFileTest {

    @Test
    void roundTripPreservesRecords() {
        List<PcapFile.Record> in = List.of(
                new PcapFile.Record(0L, new byte[]{1}),
                new PcapFile.Record(1000L, new byte[]{1, 2, 3}),
                new PcapFile.Record(1_771_000_042_987L, new byte[]{(byte) 0xff, (byte) 0xaa, 0x00}));
        List<PcapFile.Record> out = PcapFile.read(PcapFile.write(in));
        assertEquals(in.size(), out.size());
        for (int i = 0; i < in.size(); i++) {
            assertEquals(in.get(i).tsMillis(), out.get(i).tsMillis(), "record " + i + " ts");
            assertArrayEquals(in.get(i).raw(), out.get(i).raw(), "record " + i + " bytes");
        }
    }

    @Test
    void emptyWriteIsBareGlobalHeader() {
        byte[] pcap = PcapFile.write(List.of());
        assertEquals(24, pcap.length);
        // 大端 μs 魔数 + 以太网链路类型:Wireshark 可直接打开
        assertArrayEquals(new byte[]{(byte) 0xa1, (byte) 0xb2, (byte) 0xc3, (byte) 0xd4},
                Arrays.copyOfRange(pcap, 0, 4));
        assertEquals(PcapFile.LINKTYPE_ETHERNET, beInt(pcap, 20));
    }

    @Test
    void readsLittleEndianMicrosecondPcap() {
        byte[] pcap = littleEndianPcap(0xa1b2c3d4, 2_500_000, new byte[]{9, 9});   // 2.5s(μs)
        List<PcapFile.Record> out = PcapFile.read(pcap);
        assertEquals(1, out.size());
        assertEquals(2500L, out.get(0).tsMillis());
        assertArrayEquals(new byte[]{9, 9}, out.get(0).raw());
    }

    @Test
    void readsNanosecondPcap() {
        byte[] be = bigEndianPcap(0xa1b23c4d, 1_234_567_890, new byte[]{7});       // ns 精度
        assertEquals(1234L, PcapFile.read(be).get(0).tsMillis());                   // 1.23456789s → 1234ms
        byte[] le = littleEndianPcap(0xa1b23c4d, 1_234_567_890, new byte[]{7});
        assertEquals(PcapFile.read(be).get(0).tsMillis(), PcapFile.read(le).get(0).tsMillis());
    }

    @Test
    void rejectsBadMagic() {
        byte[] notPcap = new byte[24];
        assertThrows(IllegalArgumentException.class, () -> PcapFile.read(notPcap));
        assertThrows(IllegalArgumentException.class, () -> PcapFile.read(new byte[10]));
    }

    @Test
    void rejectsNonEthernetLinktype() {
        byte[] sll = littleEndianPcap(0xa1b2c3d4, 0, new byte[]{1});               // linktype=113(Linux SLL)
        sll[20] = 113;
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PcapFile.read(sll));
        assertEquals("unsupported pcap linktype 113 (only Ethernet/1 is importable)", e.getMessage());
    }

    @Test
    void rejectsTruncatedRecord() {
        byte[] pcap = bigEndianPcap(0xa1b2c3d4, 0, new byte[]{1, 2, 3, 4, 5});
        byte[] cut = Arrays.copyOf(pcap, pcap.length - 2);                          // 帧字节被截断
        assertThrows(IllegalArgumentException.class, () -> PcapFile.read(cut));
    }

    // ---- 夹具构造 ----

    private static byte[] littleEndianPcap(int magic, long frac, byte[] payload) {
        ByteBuffer b = ByteBuffer.allocate(24 + 16 + payload.length).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(magic).putShort((short) 2).putShort((short) 4).putInt(0).putInt(0)
                .putInt(262144).putInt(PcapFile.LINKTYPE_ETHERNET);
        b.putInt(0).putInt((int) frac).putInt(payload.length).putInt(payload.length).put(payload);
        return b.array();
    }

    private static byte[] bigEndianPcap(int magic, long frac, byte[] payload) {
        ByteBuffer b = ByteBuffer.allocate(24 + 16 + payload.length).order(ByteOrder.BIG_ENDIAN);
        b.putInt(magic).putShort((short) 2).putShort((short) 4).putInt(0).putInt(0)
                .putInt(262144).putInt(PcapFile.LINKTYPE_ETHERNET);
        b.putInt(0).putInt((int) frac).putInt(payload.length).putInt(payload.length).put(payload);
        return b.array();
    }

    private static int beInt(byte[] a, int off) {
        return (a[off] & 0xFF) << 24 | (a[off + 1] & 0xFF) << 16 | (a[off + 2] & 0xFF) << 8 | (a[off + 3] & 0xFF);
    }
}
