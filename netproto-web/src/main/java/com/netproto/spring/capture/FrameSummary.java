package com.netproto.spring.capture;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.List;

/**
 * 帧摘要(Wireshark 列表行模型):环形缓冲与 SSE 常驻的是这层轻量表示——
 * 原始字节 + 表格列所需的全部信息,单帧约两百字节级,几十万行也只占几十 MB。
 * <p>
 * 完整协议树不常驻:详情视图按 seq 用 {@link #raw()} 现场重解码(注解解码微秒级)。
 * src/dst/端口由 {@link PacketSummarizer} 在解码时顺手提取。
 * 字段名即 JSON 契约(SSE 直序 record):{@code ts} 与 /packets 视图对齐;
 * {@code raw} 不出网(详情走 /packet/{seq},导出走 Java 内部)。
 */
public record FrameSummary(
        long seq,
        long ts,
        String iface,
        int len,
        String path,
        List<String> layerIds,
        String src,
        String dst,
        Integer srcPort,
        Integer dstPort,
        String info,
        @JsonIgnore byte[] raw) {

    /** 表格"协议"列显示名(最深协议 id;组名映射由前端按协议元数据做)。 */
    public String protoId() {
        return layerIds.isEmpty() ? "-" : layerIds.get(layerIds.size() - 1);
    }
}
