package com.example.demo.protocol.config;

import com.example.demo.protocol.builtin.UdpSegment;
import com.example.demo.protocol.capture.CaptureEngine;
import com.example.demo.protocol.capture.RawSender;
import com.example.demo.protocol.stack.ProtocolRegistry;
import com.example.demo.protocol.stack.StackDecoder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 自动装配:classpath 扫描 @Protocol、内置栈恒注册、绑定生效、开关可用。 */
class AutoConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(NetprotoAutoConfiguration.class));

    @Test
    void scansUserPackagesAndRegistersBuiltins() {
        runner.withPropertyValues("netproto.base-packages=com.example.demo.protocol.configtest")
                .run(ctx -> {
                    assertEquals(1, ctx.getBeansOfType(ProtocolRegistry.class).size());
                    ProtocolRegistry r = ctx.getBean(ProtocolRegistry.class);
                    // 用户包协议被扫到
                    assertTrue(r.ids().contains("probe-a"));
                    // 内置栈恒注册
                    assertTrue(r.ids().containsAll(
                            List.of("ethernet", "arp", "ipv4", "icmp", "udp", "tcp")));
                    // 配套 bean 全部就位
                    assertEquals(1, ctx.getBeansOfType(StackDecoder.class).size());
                    assertEquals(1, ctx.getBeansOfType(CaptureEngine.class).size());
                    assertEquals(1, ctx.getBeansOfType(RawSender.class).size());
                    // 绑定可用:udp 7777 → probe-a
                    UdpSegment udp = new UdpSegment();
                    udp.setDstPort(7777);
                    assertEquals("probe-a", r.matchChild("udp", udp));
                });
    }

    @Test
    void enabledFalseSkipsEverything() {
        runner.withPropertyValues("netproto.enabled=false")
                .run(ctx -> assertTrue(ctx.getBeansOfType(ProtocolRegistry.class).isEmpty()));
    }
}
