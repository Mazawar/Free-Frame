package com.netproto.spring.capture;

import jakarta.annotation.PreDestroy;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * BPF 表达式离线校验:在「仅 24 字节全局头、零分组」的以太网 pcap 临时文件的离线句柄上
 * setFilter —— 不开网卡、不依赖设备,却与抓包路径走同一个 libpcap 编译器
 * ({@code pcap_compile}),因此「校验通过 = 实际采集可用」,不存在第二套语法解释
 * (tcpdump 读文件应用过滤器即同机制)。
 * <p>
 * 为何不用更轻的 {@code pcap_open_dead}:libpcap 1.10 起禁止对 dead 句柄
 * {@code pcap_setfilter};而离线文件句柄合法,且 pcap4j 的 setFilter 成败两条路径都会
 * {@code pcap_freecode},长期频繁校验(前端逐键)无原生内存泄漏 ——
 * {@code Pcaps.compileFilter} 静态重载返回的 BpfProgram 无公开释放口,不复用。
 * <p>
 * 句柄进程内复用,validate 串行(pcap_t 非线程安全);编译微秒级,串行无瓶颈。
 * 含主机名/服务名的表达式编译期会做 DNS/services 解析,离线时报 unknown host ——
 * 这正是真实抓包时的行为,如实透出。
 */
public final class BpfValidator {

    /** 校验结论。error 为 pcap4j/libpcap 原文(如 "…syntax error in filter expression")。 */
    public record Result(boolean ok, String error) {}

    private PcapHandle offline;
    private Path file;

    private PcapHandle handle() throws PcapNativeException, IOException {
        if (offline == null) {
            file = Files.createTempFile("netproto-bpf-check", ".pcap");
            Files.write(file, PcapFile.write(List.of()));
            file.toFile().deleteOnExit();
            offline = Pcaps.openOffline(file.toString());
        }
        return offline;
    }

    /** 空表达式合法(= 不过滤);其余交给 libpcap 裁决。 */
    public synchronized Result validate(String expr) {
        if (expr == null || expr.isBlank()) {
            return new Result(true, null);
        }
        try {
            return compile(expr);
        } catch (NotOpenException e) {
            // 理论不可达(句柄除 @PreDestroy 无人关闭);防御:重建一次
            close();
            try {
                return compile(expr);
            } catch (Exception retry) {
                return new Result(false, retry.getMessage());
            }
        } catch (PcapNativeException | IOException e) {
            return new Result(false, e.getMessage());
        }
    }

    private Result compile(String expr) throws PcapNativeException, NotOpenException, IOException {
        handle().setFilter(expr, BpfProgram.BpfCompileMode.OPTIMIZE);
        return new Result(true, null);
    }

    @PreDestroy
    public synchronized void close() {
        if (offline != null) {
            offline.close();
            offline = null;
        }
        if (file != null) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException ignored) {
                // Windows 上句柄释放偶有延迟,deleteOnExit 兜底
            }
            file = null;
        }
    }
}
