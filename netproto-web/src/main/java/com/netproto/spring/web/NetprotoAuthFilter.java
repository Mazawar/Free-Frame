package com.netproto.spring.web;

import com.netproto.spring.config.NetprotoProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * API 访问令牌过滤器:netproto.auth-token 非空时,/api/netproto/** 全部要求匹配令牌。
 * <p>
 * 本组件的端点含原始帧注入(/send)、全量流量导出(/export)、网卡清单(/interfaces)——
 * starter 不内置用户体系,宿主嵌入生产或暴露到不可信网络时以此最小门槛防护;
 * 默认空令牌 = 不启用(demo 本机用法,配合 server.address=127.0.0.1)。
 * <p>
 * 校验顺序:自定义头 X-Netproto-Token 优先;无头时接受 ?token=(浏览器 EventSource
 * 无法携带自定义头)。恒定时间比较防时序侧信道。观测台静态资源不受限(页面壳本身
 * 无敏感数据,数据全走被保护的 API)。
 */
public class NetprotoAuthFilter extends OncePerRequestFilter {

    static final String TOKEN_HEADER = "X-Netproto-Token";
    static final String TOKEN_PARAM = "token";

    private final byte[] expected;

    public NetprotoAuthFilter(NetprotoProperties props) {
        this.expected = props.getAuthToken().getBytes(StandardCharsets.UTF_8);
    }

    public boolean isEnabled() {
        return expected.length > 0;
    }

    /** 拦截范围由 FilterRegistrationBean 的 urlPatterns(/api/netproto/*)限定,
     *  与部署上下文路径无关;此处只判启用开关。 */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !isEnabled();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String provided = request.getHeader(TOKEN_HEADER);
        if (provided == null || provided.isEmpty()) {
            provided = request.getParameter(TOKEN_PARAM);
        }
        if (provided == null || !MessageDigest.isEqual(expected,
                provided.getBytes(StandardCharsets.UTF_8))) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"missing or invalid token"
                    + " (X-Netproto-Token header or ?token=)\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
