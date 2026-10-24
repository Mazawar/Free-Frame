package com.netproto.demo.protocol.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 令牌鉴权端到端:netproto.auth-token 非空时 /api/netproto/** 未带/错带令牌 401,
 * 头或 ?token= 均放行;观测台静态页不受限(数据全走被保护的 API)。
 */
@SpringBootTest(properties = {
        "netproto.base-packages=com.netproto.protocols.builtin",
        "netproto.auth-token=topsecret",
}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthTokenApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void apiRequiresToken() throws Exception {
        mockMvc.perform(get("/api/netproto/config"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/netproto/config").header("X-Netproto-Token", "wrong"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void apiAcceptsHeaderOrQueryParam() throws Exception {
        mockMvc.perform(get("/api/netproto/config").header("X-Netproto-Token", "topsecret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rootProtocol").value("ethernet"));
        // EventSource 场景:令牌经查询参数
        mockMvc.perform(get("/api/netproto/config").queryParam("token", "topsecret"))
                .andExpect(status().isOk());
    }
}
