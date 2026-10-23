package com.netproto.demo.protocol.web;

import com.netproto.demo.protocol.powerdist.PowerDistSamples;
import com.netproto.spring.capture.SessionManager;
import com.netproto.stack.StackEncoder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 信号视图端点:注入状态上报样例后,按协议字段抽出的时间序列应逐帧成点(旧→新);
 *  未含该协议层的帧不产点;未知协议/字段 400。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class SignalsDemoTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SessionManager sessions;

    @Autowired
    private StackEncoder encoder;

    @Test
    void signalSeriesExtractsFieldValues() throws Exception {
        var s = sessions.defaultSession();
        var samples = new PowerDistSamples(encoder);
        for (int i = 0; i < 3; i++) {
            s.inject("test", samples.statusReport());   // 每次电压/电流/温度/状态随机扰动
        }
        s.inject("test", samples.register());           // 注册帧:无 pd-status-report 层,不应产点

        String base = "/api/netproto/sessions/" + s.id() + "/signals";
        mockMvc.perform(get(base).param("proto", "pd-status-report").param("field", "voltage"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kind").value("analog"))
                .andExpect(jsonPath("$.points.length()").value(3))
                .andExpect(jsonPath("$.points[0].v").isNumber());

        mockMvc.perform(get(base).param("proto", "pd-status-report").param("field", "runStatus"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.points.length()").value(3));

        mockMvc.perform(get(base).param("proto", "pd-status-report").param("field", "nope"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get(base).param("proto", "nope").param("field", "v"))
                .andExpect(status().isBadRequest());
    }
}
