package com.netproto.spring.web;

import com.netproto.spring.config.NetprotoProperties;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * API 令牌过滤器:启用(非空 token)时未带/错带令牌一律 401,
 * 头或查询参数携带均可(EventSource 无法带自定义头);空 token = 完全放行(demo 默认)。
 */
class NetprotoAuthFilterTest {

    private static NetprotoProperties props(String token) {
        NetprotoProperties p = new NetprotoProperties();
        p.setAuthToken(token);
        return p;
    }

    /** 链是否被放行(到达控制器)。 */
    private static boolean passes(NetprotoAuthFilter f, MockHttpServletRequest req) throws Exception {
        MockHttpServletResponse resp = new MockHttpServletResponse();
        boolean[] chained = {false};
        FilterChain chain = (request, response) -> chained[0] = true;
        f.doFilter(req, resp, chain);
        if (resp.getStatus() == 401) {
            assertFalse(chained[0], "401 时不得继续过滤链");
        }
        return chained[0];
    }

    @Test
    void emptyTokenDisablesFilter() throws Exception {
        NetprotoAuthFilter f = new NetprotoAuthFilter(props(""));
        assertFalse(f.isEnabled());
        assertTrue(passes(f, new MockHttpServletRequest("GET", "/api/netproto/export")));
    }

    @Test
    void enabledRejectsMissingAndWrongToken() throws Exception {
        NetprotoAuthFilter f = new NetprotoAuthFilter(props("s3cret"));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        f.doFilter(new MockHttpServletRequest("GET", "/api/netproto/export"), resp,
                (req, res) -> { throw new AssertionError("不得放行"); });
        assertEquals(401, resp.getStatus());

        MockHttpServletRequest wrong = new MockHttpServletRequest("GET", "/api/netproto/config");
        wrong.addHeader(NetprotoAuthFilter.TOKEN_HEADER, "wrong");
        resp = new MockHttpServletResponse();
        f.doFilter(wrong, resp, (req, res) -> { throw new AssertionError("不得放行"); });
        assertEquals(401, resp.getStatus());
    }

    @Test
    void enabledAcceptsHeaderAndQueryParam() throws Exception {
        NetprotoAuthFilter f = new NetprotoAuthFilter(props("s3cret"));
        MockHttpServletRequest viaHeader = new MockHttpServletRequest("GET", "/api/netproto/export");
        viaHeader.addHeader(NetprotoAuthFilter.TOKEN_HEADER, "s3cret");
        assertTrue(passes(f, viaHeader));

        // EventSource 无法带自定义头:查询参数同样有效
        MockHttpServletRequest viaParam = new MockHttpServletRequest("GET", "/api/netproto/sessions/x/stream");
        viaParam.setQueryString("token=s3cret");
        viaParam.setParameter(NetprotoAuthFilter.TOKEN_PARAM, "s3cret");
        assertTrue(passes(f, viaParam));
    }
}
