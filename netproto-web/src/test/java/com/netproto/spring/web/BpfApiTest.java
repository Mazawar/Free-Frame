package com.netproto.spring.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** BPF 智能提示/校验端点:validate 的裁决来自 libpcap 编译(死句柄,与抓包同一编译器),
 *  hints 的配方来自注册表 @BindOn 推导(本测试环境只有内置栈)。 */
@SpringBootTest(classes = BpfApiTest.App.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class BpfApiTest {

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class App {
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    void validFiltersCompile() throws Exception {
        for (String f : new String[]{"tcp port 502", "host 192.0.2.1",
                "ether proto 0x0800 and greater 64", "not arp and (udp port 53 or tcp port 53)"}) {
            mockMvc.perform(get("/api/netproto/bpf/validate").param("expr", f))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.ok").value(true));
        }
    }

    @Test
    void syntaxErrorsCarryLibpcapMessage() throws Exception {
        mockMvc.perform(get("/api/netproto/bpf/validate").param("expr", "tcp portt 502"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.error", containsString("syntax")));
        // 裸 host(缺参数值)同样是编译失败
        mockMvc.perform(get("/api/netproto/bpf/validate").param("expr", "host"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.error").isNotEmpty());
    }

    @Test
    void blankExpressionIsValid() throws Exception {
        // 空 = 不过滤,与 startCapture 的 bpf 缺省语义一致
        mockMvc.perform(get("/api/netproto/bpf/validate").param("expr", ""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true));
    }

    @Test
    void overlongExpressionRejected() throws Exception {
        mockMvc.perform(get("/api/netproto/bpf/validate").param("expr", "a".repeat(3000)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void hintsCarryRegistryRecipesAndLocalAddresses() throws Exception {
        mockMvc.perform(get("/api/netproto/bpf/hints"))
                .andExpect(status().isOk())
                // 内置栈:ipv4 挂 ethernet(etherType == 0x0800)→ 配方 ether proto 0x0800
                .andExpect(jsonPath("$.recipes[?(@.expr == 'ether proto 0x0800')]").exists())
                .andExpect(jsonPath("$.localAddresses").isArray());
    }
}
