package com.netproto.demo.protocol.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** BPF 提示素材(demo 环境):用户业务协议的端口分派应被自动推导成配方 ——
 *  提示与注册表同源,新协议上线无需改提示清单。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class BpfHintsDemoTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void demoPortsDerivedAsRecipes() throws Exception {
        mockMvc.perform(get("/api/netproto/bpf/hints"))
                .andExpect(status().isOk())
                // pd=9000 / iot=9001 / devcomm=9002(各 @BindOn 的 udp 端口分派)
                .andExpect(jsonPath("$.recipes[?(@.expr == 'udp port 9000')]").exists())
                .andExpect(jsonPath("$.recipes[?(@.expr == 'udp port 9001')]").exists())
                .andExpect(jsonPath("$.recipes[?(@.expr == 'udp port 9002')]").exists())
                // 总数 = 3 个 demo 端口配方 + 4 个内置 EtherType 配方(ipv4/arp/vlan/ipv6);
                // 选择子在业务头内的层(pd 的 signalType 子协议)BPF 表达不了,不得出现假配方
                .andExpect(jsonPath("$.recipes.length()").value(7));
    }
}
