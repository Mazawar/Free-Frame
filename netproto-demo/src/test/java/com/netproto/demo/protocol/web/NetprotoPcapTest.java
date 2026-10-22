package com.netproto.demo.protocol.web;

import com.netproto.spring.capture.PcapFile;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * pcap 导出/导入冒烟。独立成类 + {@link DirtiesContext}(每方法后重建):导入会向环形缓冲注入帧,
 * 不能污染假定空引擎的 {@link NetprotoApiTest},类内方法间也互不干扰。
 */
@SpringBootTest(properties = "netproto.base-packages=com.netproto.protocols.builtin")
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class NetprotoPcapTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void exportEmptyRingIsBarePcapHeader() throws Exception {
        MvcResult r = mockMvc.perform(get("/api/netproto/export"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.matchesPattern("attachment; filename=netproto-default-0f-.*\\.pcap")))
                .andReturn();
        byte[] pcap = r.getResponse().getContentAsByteArray();
        assertEquals(24, pcap.length);   // 仅全局头
        assertEquals(0xa1, pcap[0] & 0xFF);
        assertEquals(0xb2, pcap[1] & 0xFF);
        assertEquals(0xc3, pcap[2] & 0xFF);
        assertEquals(0xd4, pcap[3] & 0xFF);
    }

    @Test
    void importPcapInjectsFramesWithOriginalTimestamps() throws Exception {
        // 以太网帧:dst/src MAC + 未知 etherType 0x1234 + 载荷 → 解析停在 ethernet 层
        byte[] frame = {0x33, 0x33, 0, 0, 0, 1, (byte) 0x88, (byte) 0xb9, 51, (byte) 0xe2, 0x48, (byte) 0xa5,
                0x12, 0x34, 1, 2, 3, 4};
        byte[] pcap = PcapFile.write(List.of(
                new PcapFile.Record(1_700_000_000_000L, frame),
                new PcapFile.Record(1_700_000_001_234L, frame)));

        mockMvc.perform(multipart("/api/netproto/import").file(
                        new MockMultipartFile("file", "sample.pcap", "application/octet-stream", pcap)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.imported").value(2));

        mockMvc.perform(get("/api/netproto/packets?limit=10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[1].ts").value(1_700_000_000_000L))   // 返回新→旧,末位是最旧一帧
                .andExpect(jsonPath("$[1].path").value("ethernet"));

        // 非法文件(非 pcap)→ 400
        mockMvc.perform(multipart("/api/netproto/import").file(
                        new MockMultipartFile("file", "bad.pcap", "application/octet-stream", new byte[10])))
                .andExpect(status().isBadRequest());
    }

    @Test
    void exportAfterImportRoundTrips() throws Exception {
        byte[] frame = {0x33, 0x33, 0, 0, 0, (byte) 0xfb, (byte) 0x88, (byte) 0xb9, 51, (byte) 0xe2, 0x48, (byte) 0xa5,
                0x12, 0x34, 9};
        byte[] pcap = PcapFile.write(List.of(new PcapFile.Record(1_234_567L, frame)));
        mockMvc.perform(multipart("/api/netproto/import").file(
                        new MockMultipartFile("file", "rt.pcap", "application/octet-stream", pcap)))
                .andExpect(status().isOk());

        MvcResult r = mockMvc.perform(get("/api/netproto/export"))
                .andExpect(status().isOk())
                .andReturn();
        List<PcapFile.Record> back = PcapFile.read(r.getResponse().getContentAsByteArray());
        assertEquals(1, back.size());
        assertEquals(1_234_567L, back.get(0).tsMillis());
        assertEquals(frame.length, back.get(0).raw().length);
    }

    @Test
    void packetDetailEndpointReDecodesOnDemand() throws Exception {
        byte[] frame = {0x33, 0x33, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0x12, 0x34, 1, 2, 3, 4};
        byte[] pcap = PcapFile.write(List.of(new PcapFile.Record(1_700_000_000_000L, frame)));
        mockMvc.perform(multipart("/api/netproto/import").file(
                        new MockMultipartFile("file", "d.pcap", "application/octet-stream", pcap)))
                .andExpect(status().isOk());

        // 列表 = 轻量摘要(无协议树/hex)
        mockMvc.perform(get("/api/netproto/packets?limit=10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].layerIds[0]").value("ethernet"))
                .andExpect(jsonPath("$[0].src").exists())
                .andExpect(jsonPath("$[0].info").exists())
                .andExpect(jsonPath("$[0].layers").doesNotExist())
                .andExpect(jsonPath("$[0].hex").doesNotExist());

        // 详情 = 按需重解码的完整树 + hex
        mockMvc.perform(get("/api/netproto/packet/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.seq").value(1))
                .andExpect(jsonPath("$.path").value("ethernet"))
                .andExpect(jsonPath("$.layers[0].id").value("ethernet"))
                .andExpect(jsonPath("$.layers[0].fields.dstMac").exists())
                .andExpect(jsonPath("$.hex").isNotEmpty());

        // 已淘汰的 seq → 404
        mockMvc.perform(get("/api/netproto/packet/9999"))
                .andExpect(status().isNotFound());
    }

    @Test
    void templateEndpointBuildsChainWithDefaults() throws Exception {
        // 目标 tcp(本上下文仅注册内置栈)→ 自动推导 ethernet▸ipv4▸tcp 三层
        mockMvc.perform(get("/api/netproto/template").param("path", "tcp"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.layers.length()").value(3))
                .andExpect(jsonPath("$.layers[0].protocol").value("ethernet"))
                .andExpect(jsonPath("$.layers[1].protocol").value("ipv4"))
                .andExpect(jsonPath("$.layers[2].protocol").value("tcp"))
                // 默认值来自 POJO 字段初始值(tcp.dataOffset=5, ipv4.ttl=64)
                .andExpect(jsonPath("$.layers[2].fields.dataOffset").value(5))
                .andExpect(jsonPath("$.layers[1].fields.ttl").value(64))
                // 自动字段(@ChecksumField 校验和)不进模板;tcp.checksum 无注解属普通字段,保留
                .andExpect(jsonPath("$.layers[1].fields.headerChecksum").doesNotExist())
                .andExpect(jsonPath("$.layers[2].fields.checksum").value(0));

        mockMvc.perform(get("/api/netproto/template").param("path", "no-such-proto"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void importReplacesExistingRingContents() throws Exception {
        // 先导入 2 帧
        byte[] frame = {0x33, 0x33, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0x12, 0x34, 1, 2};
        byte[] two = PcapFile.write(List.of(
                new PcapFile.Record(1000L, frame), new PcapFile.Record(2000L, frame)));
        mockMvc.perform(multipart("/api/netproto/import").file(
                        new MockMultipartFile("file", "a.pcap", "application/octet-stream", two)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.imported").value(2));

        // 再导入 1 帧:打开文件语义,环形缓冲被替换(不是追加)
        byte[] one = PcapFile.write(List.of(new PcapFile.Record(3000L, frame)));
        mockMvc.perform(multipart("/api/netproto/import").file(
                        new MockMultipartFile("file", "b.pcap", "application/octet-stream", one)))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/netproto/packets?limit=100"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].ts").value(3000L))
                .andExpect(jsonPath("$[0].seq").value(1));   // 计数随重置,导入帧重新编号
    }
}
