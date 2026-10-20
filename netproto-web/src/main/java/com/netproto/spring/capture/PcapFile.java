package com.netproto.spring.capture;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 标准 pcap 文件读写(24 字节全局头 + [16 字节记录头 + 原始帧]*,与 tcpdump/Wireshark 互通)。
 * <p>
 * 写:微秒精度、大端(魔数 0xa1b2c3d4)、链路类型 LINKTYPE_ETHERNET。
 * 读:接受四种魔数(μs/ns × 大/小端,Wireshark/tcpdump/dumpcap 各种写出组合),
 * 仅接受以太网链路类型——本引擎的根协议假定;其余情况明确报错而非解析出乱码。
 */
public final class PcapFile {

    /** DLT_EN10MB:IEEE 802.3 Ethernet(引擎根协议 ethernet 的链路假定)。 */
    public static final int LINKTYPE_ETHERNET = 1;

    /** 一条 pcap 记录:毫秒时间戳 + 原始帧字节。 */
    public record Record(long tsMillis, byte[] raw) {}

    private static final int MAGIC_US = 0xa1b2c3d4;
    private static final int MAGIC_NS = 0xa1b23c4d;

    private PcapFile() {}

    /** 全局头 + 全部记录(旧→新);空列表得到仅含 24 字节全局头的合法 pcap。 */
    public static byte[] write(List<Record> records) {
        try {
            ByteArrayOutputStream buf = new ByteArrayOutputStream(24 + records.size() * 40);
            DataOutputStream out = new DataOutputStream(buf);
            out.writeInt(MAGIC_US);                 // 大端 μs
            out.writeShort(2);                      // version major
            out.writeShort(4);                      // version minor
            out.writeInt(0);                        // thiszone(全部按 GMT 解释)
            out.writeInt(0);                        // sigfigs
            out.writeInt(262144);                   // snaplen
            out.writeInt(LINKTYPE_ETHERNET);
            for (Record r : records) {
                out.writeInt((int) (r.tsMillis() / 1000L));
                out.writeInt((int) (r.tsMillis() % 1000L * 1000L));
                out.writeInt(r.raw().length);
                out.writeInt(r.raw().length);
                out.write(r.raw());
            }
            return buf.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);      // 纯内存流,理论不可达
        }
    }

    /** 解析整个文件;非 pcap / 非以太网链路 / 截断记录抛 IllegalArgumentException(REST 层映射 400)。 */
    public static List<Record> read(byte[] file) {
        if (file.length < 24) {
            throw new IllegalArgumentException("not a pcap file: shorter than the 24-byte global header");
        }
        int magicRaw = beInt(file, 0);
        boolean littleEndian;
        boolean nanos;
        if (magicRaw == MAGIC_US) {
            littleEndian = false;
            nanos = false;
        } else if (magicRaw == MAGIC_NS) {
            littleEndian = false;
            nanos = true;
        } else if (Integer.reverseBytes(magicRaw) == MAGIC_US) {
            littleEndian = true;
            nanos = false;
        } else if (Integer.reverseBytes(magicRaw) == MAGIC_NS) {
            littleEndian = true;
            nanos = true;
        } else {
            throw new IllegalArgumentException(
                    "not a pcap file: unknown magic 0x" + Integer.toUnsignedString(magicRaw, 16));
        }
        int linktype = (int) u32(file, 20, littleEndian);
        if (linktype != LINKTYPE_ETHERNET) {
            throw new IllegalArgumentException(
                    "unsupported pcap linktype " + linktype + " (only Ethernet/1 is importable)");
        }
        List<Record> out = new ArrayList<>();
        int off = 24;
        while (off < file.length) {
            if (file.length - off < 16) {
                throw new IllegalArgumentException("truncated pcap: record header cut at offset " + off);
            }
            long sec = u32(file, off, littleEndian);
            long frac = u32(file, off + 4, littleEndian);   // μs 或 ns,由魔数决定
            int incl = (int) u32(file, off + 8, littleEndian);
            if (incl < 0 || file.length - off - 16 < incl) {
                throw new IllegalArgumentException(
                        "truncated pcap: record needs " + incl + " bytes at offset " + (off + 16));
            }
            long ms = sec * 1000L + (nanos ? frac / 1_000_000L : frac / 1000L);
            byte[] raw = new byte[incl];
            System.arraycopy(file, off + 16, raw, 0, incl);
            out.add(new Record(ms, raw));
            off += 16 + incl;
        }
        return out;
    }

    private static int beInt(byte[] b, int off) {
        return (b[off] & 0xFF) << 24 | (b[off + 1] & 0xFF) << 16 | (b[off + 2] & 0xFF) << 8 | (b[off + 3] & 0xFF);
    }

    private static long u32(byte[] b, int off, boolean littleEndian) {
        int v = beInt(b, off);
        return (littleEndian ? Integer.reverseBytes(v) : v) & 0xFFFFFFFFL;
    }
}
