package com.example.demo.web;

import com.example.demo.protocol.biz.PrivateSamples;
import com.example.netproto.spring.capture.CaptureEngine;
import com.example.netproto.stack.StackEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 私有协议族演示端点:组装三种形态(XETH 直挂以太网 / GXTP over UDP / MTALK over TCP)
 * 的样例报文并注入解析管线 —— 无需真实流量,页面即可看到完整解析效果。
 */
@RestController
@RequestMapping("/api/demo")
public class DemoSampleController {

    private final CaptureEngine capture;
    private final PrivateSamples samples;

    public DemoSampleController(CaptureEngine capture, StackEncoder encoder) {
        this.capture = capture;
        this.samples = new PrivateSamples(encoder);
    }

    /** 注入全部 8 个私有协议样例帧,返回各帧长度。 */
    @PostMapping("/samples")
    public Map<String, Object> injectSamples() {
        Map<String, Integer> frames = new LinkedHashMap<>();
        frames.put("xeth-telemetry", samples.xethTelemetry().length);
        frames.put("xeth-alarm", samples.xethAlarm().length);
        frames.put("gxtp-login", samples.gxLogin().length);
        frames.put("gxtp-telemetry", samples.gxTelemetry().length);
        frames.put("gxtp-config", samples.gxConfig().length);
        frames.put("gxtp-file-chunk", samples.gxFileChunk().length);
        frames.put("mtalk-hello", samples.mtalkHello().length);
        frames.put("mtalk-events", samples.mtalkEvents().length);

        // 逐帧注入(同序)
        capture.inject("demo", samples.xethTelemetry());
        capture.inject("demo", samples.xethAlarm());
        capture.inject("demo", samples.gxLogin());
        capture.inject("demo", samples.gxTelemetry());
        capture.inject("demo", samples.gxConfig());
        capture.inject("demo", samples.gxFileChunk());
        capture.inject("demo", samples.mtalkHello());
        capture.inject("demo", samples.mtalkEvents());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "injected");
        out.put("frames", frames);
        return out;
    }
}
