package com.netproto.demo.protocol.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Web 层冒烟:协议元数据/状态/最近帧三个只读端点。 */
@SpringBootTest(properties = "netproto.base-packages=com.netproto.protocols.builtin",
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class NetprotoApiTest {

    @Autowired
    private MockMvc mockMvc;

    @org.springframework.beans.factory.annotation.Value("${local.server.port}")
    private int port;

    @Test
    void protocolsEndpointListsBuiltins() throws Exception {
        mockMvc.perform(get("/api/netproto/protocols"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == 'ethernet')]").exists())
                .andExpect(jsonPath("$[?(@.id == 'ipv4')]").exists())
                .andExpect(jsonPath("$[?(@.id == 'ipv4')].fields[?(@.name == 'totalLength')]").exists());
    }

    @Test
    void statusEndpoint() throws Exception {
        mockMvc.perform(get("/api/netproto/capture/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.running").value(false))
                .andExpect(jsonPath("$.captured").value(0));
    }

    @Test
    void packetsEndpointEmpty() throws Exception {
        mockMvc.perform(get("/api/netproto/packets"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void configEndpointExposesRuntimeProperties() throws Exception {
        mockMvc.perform(get("/api/netproto/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rootProtocol").value("ethernet"))
                .andExpect(jsonPath("$.ringSize").value(100000))
                .andExpect(jsonPath("$.ringBytes").value(16 * 1024 * 1024))
                .andExpect(jsonPath("$.snaplen").value(65536));
    }

    @Test
    void observatoryUiServedAtBasePath() {
        // 观测台挂载在专属路径(netproto.ui-base-path,默认 /netproto),根路径留给宿主应用。
        // 走真实服务器:MockMvc 对「转发 → 静态资源」链路返回空体/404 假象
        // (正文断言已在 netproto-web 的 UiBasePathTest 用真实端口覆盖)。
        try {
            java.net.http.HttpResponse<String> r = java.net.http.HttpClient.newHttpClient().send(
                    java.net.http.HttpRequest.newBuilder(
                            java.net.URI.create("http://127.0.0.1:" + port + "/netproto/")).build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
            org.junit.jupiter.api.Assertions.assertEquals(200, r.statusCode());
            org.junit.jupiter.api.Assertions.assertTrue(r.body().contains("id=\"app\""));
            java.net.http.HttpResponse<String> root = java.net.http.HttpClient.newHttpClient().send(
                    java.net.http.HttpRequest.newBuilder(
                            java.net.URI.create("http://127.0.0.1:" + port + "/index.html")).build(),
                    java.net.http.HttpResponse.BodyHandlers.ofString());
            org.junit.jupiter.api.Assertions.assertEquals(404, root.statusCode());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
