package com.netproto.demo.web;

import com.netproto.demo.protocol.powerdist.PowerDistSamples;
import com.netproto.spring.capture.SessionManager;
import com.netproto.stack.StackEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 智能配电样例注入端点:组装注册/注册许可/状态上报/参数查询响应四个完整以太网帧
 * 注入解析管线,页面无需真实流量即可看到 UDP 9000 协议栈解析效果。
 */
@RestController
@RequestMapping("/api/demo")
public class DemoSampleController {

    private final SessionManager sessions;
    private final PowerDistSamples samples;

    public DemoSampleController(SessionManager sessions, StackEncoder encoder) {
        this.sessions = sessions;
        this.samples = new PowerDistSamples(encoder);
    }

    /** 注入配电协议交互样例(注册 → 许可 → 上报 → 参数响应),返回各帧长度。
     *  可选 ?session=sN 注入到指定会话(页面会话化后默认会话页面看不到);缺省仍进 default。 */
    @PostMapping("/samples")
    public Map<String, Object> injectSamples(
            @RequestParam(required = false) String session) {
        com.netproto.spring.capture.CaptureSession target = sessions.defaultSession();
        if (session != null && !session.isBlank()) {
            target = sessions.get(session);
            if (target == null) {
                throw new IllegalArgumentException("unknown session: " + session);
            }
        }
        byte[][] frames = {
                samples.register(),
                samples.registerGrant(),
                samples.statusReport(),
                samples.paramQueryResp(),
        };
        Map<String, Integer> sizes = new LinkedHashMap<>();
        sizes.put("pd-reg", frames[0].length);
        sizes.put("pd-reg-grant", frames[1].length);
        sizes.put("pd-status-report", frames[2].length);
        sizes.put("pd-param-query-resp", frames[3].length);
        for (byte[] f : frames) {
            target.inject("demo", f);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "injected");
        out.put("frames", sizes);
        return out;
    }
}
