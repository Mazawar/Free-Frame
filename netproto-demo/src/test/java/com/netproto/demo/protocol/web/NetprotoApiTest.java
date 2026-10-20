package com.netproto.demo.protocol.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Web 层冒烟:协议元数据/状态/最近帧三个只读端点。 */
@SpringBootTest(properties = "netproto.base-packages=com.netproto.protocols.builtin")
@AutoConfigureMockMvc
class NetprotoApiTest {

    @Autowired
    private MockMvc mockMvc;

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
    void indexPageServed() throws Exception {
        mockMvc.perform(get("/index.html"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Netproto")));
    }
}
