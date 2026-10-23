package com.netproto.demo.protocol.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netproto.demo.protocol.powerdist.PowerDistSamples;
import com.netproto.spring.capture.SessionManager;
import com.netproto.stack.StackEncoder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 流量分析/追踪端点:注入样例后聚合会话/协议/时间线;
 *  追踪端点按端点对取帧,端点参数互换(反方向)应同样命中 —— 双向语义。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class TrafficDemoTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SessionManager sessions;

    @Autowired
    private StackEncoder encoder;

    @Test
    void trafficAggregatesAndTracesBothDirections() throws Exception {
        var s = sessions.registerIdle("traffic-test");
        try {
            var samples = new PowerDistSamples(encoder);
            for (int i = 0; i < 2; i++) {
                s.inject("test", samples.register());        // 终端 → 平台(51888 → 9000)
                s.inject("test", samples.registerGrant());   // 平台 → 终端(9000 → 51888)
            }

            MvcResult r = mockMvc.perform(get("/api/netproto/sessions/traffic-test/traffic"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.window.frames").value(4))
                    .andExpect(jsonPath("$.timeline.buckets.length()").isNotEmpty())
                    .andExpect(jsonPath("$.protocols[?(@.id == 'pd-reg')]").exists())
                    .andExpect(jsonPath("$.protocols[?(@.id == 'pd-reg-grant')]").exists())
                    .andReturn();
            JsonNode root = mapper.readTree(r.getResponse().getContentAsString());
            JsonNode convs = root.get("conversations");
            // 样例端口形态:register 51888→9000,grant 9000→9000 —— 两条会话各 2 帧
            assertThat(convs.size()).isGreaterThanOrEqualTo(2);
            JsonNode c0 = convs.get(0);
            assertThat(c0.get("frames").asInt()).isEqualTo(2);

            // 追踪:按该会话端点取帧应命中 2 帧;端点参数整体互换(反方向查询)同样命中
            // —— 双向归一/双向匹配是会话语义的核心
            for (boolean swapped : new boolean[]{false, true}) {
                MvcResult tr = mockMvc.perform(get("/api/netproto/sessions/traffic-test/traffic/frames")
                                .param("src", (swapped ? c0.get("dstHost") : c0.get("srcHost")).asText())
                                .param("dst", (swapped ? c0.get("srcHost") : c0.get("dstHost")).asText())
                                .param("srcPort", (swapped ? c0.get("dstPort") : c0.get("srcPort")).asText())
                                .param("dstPort", (swapped ? c0.get("srcPort") : c0.get("dstPort")).asText()))
                        .andExpect(status().isOk())
                        .andReturn();
                JsonNode rows = mapper.readTree(tr.getResponse().getContentAsString());
                assertThat(rows.size()).isEqualTo(2);
                assertThat(rows.get(0).get("seq").asLong()).isLessThanOrEqualTo(rows.get(1).get("seq").asLong());
            }
        } finally {
            sessions.delete("traffic-test");
        }
    }
}
