package com.netproto.demo.protocol.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 2026-10-24 审计加固回归:注入/发包端点的体积与结构上限(JSON body 不受 maxPostSize
 * 约束,此前单请求可瞬时分配任意大小内存),以及 /packets 的 since 增量补拉。
 */
@SpringBootTest(properties = "netproto.base-packages=com.netproto.protocols.builtin",
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class HardeningApiTest {

    @Autowired
    private MockMvc mockMvc;

    private static final String ETH_FRAME_HEX = "ffffffffffff001122334455" + "88b2" + "01";

    @Test
    void injectOversizedFrameRejected() throws Exception {
        // 131073 字节 > MAX_INJECT_BYTES(128KB):hex 长度 262146
        String hex = "ab".repeat(128 * 1024 + 1);
        mockMvc.perform(post("/api/netproto/inject")
                        .contentType("application/json")
                        .content("{\"hex\":\"" + hex + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("too large")));
    }

    @Test
    void injectOddLengthStillRejected() throws Exception {
        mockMvc.perform(post("/api/netproto/inject")
                        .contentType("application/json")
                        .content("{\"hex\":\"abc\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void sendTooManyLayersRejected() throws Exception {
        // 17 层 > MAX_SEND_LAYERS(16)
        StringBuilder body = new StringBuilder("{\"iface\":\"x\",\"layers\":[");
        for (int i = 0; i < 17; i++) {
            if (i > 0) {
                body.append(',');
            }
            body.append("{\"protocol\":\"ethernet\"}");
        }
        body.append("]}");
        mockMvc.perform(post("/api/netproto/send")
                        .contentType("application/json")
                        .content(body.toString()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(
                        org.hamcrest.Matchers.containsString("too many layers")));
    }

    /** 独立会话注入 3 帧后 since 增量:只返回 seq 大于 since 的帧(断线重连只拉缺口)。
     *  用独立命名会话而非 default:本类与 NetprotoApiTest 共享同一 Spring 上下文,
     *  污染 default 会破坏其 captured==0 断言。 */
    @Test
    void packetsSinceReturnsOnlyNewerFrames() throws Exception {
        String sid = "hardening-since-1";
        mockMvc.perform(post("/api/netproto/sessions")
                        .contentType("application/json")
                        .content("{\"id\":\"" + sid + "\"}"))
                .andExpect(status().isOk());
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/api/netproto/sessions/" + sid + "/inject")
                            .contentType("application/json")
                            .content("{\"hex\":\"" + ETH_FRAME_HEX + "\"}"))
                    .andExpect(status().isOk());
        }
        mockMvc.perform(get("/api/netproto/sessions/" + sid + "/packets?limit=100"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(3));
        mockMvc.perform(get("/api/netproto/sessions/" + sid + "/packets?limit=100&since=1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[1].seq").value(2))    // 新→旧:首行是最新
                .andExpect(jsonPath("$[0].seq").value(3));
    }
}
