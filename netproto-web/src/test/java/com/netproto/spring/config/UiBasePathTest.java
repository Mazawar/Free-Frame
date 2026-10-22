package com.netproto.spring.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 观测台 UI 挂载在专属路径(starter 嵌入宿主工程时不占根路径):
 * 默认 /netproto;REST 保持 /api/netproto/** 不变;根路径 / 不再暴露观测台。
 * 真实内嵌服务器断言(JDK HttpClient,无 Boot 测试客户端依赖)。
 */
@SpringBootTest(classes = UiBasePathTest.App.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UiBasePathTest {

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class App {
    }

    @Value("${local.server.port}")
    int port;

    private final HttpClient http = HttpClient.newHttpClient();

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void uiServedAtDefaultBasePath() throws Exception {
        for (String path : new String[]{"/netproto", "/netproto/"}) {
            HttpResponse<String> r = get(path);
            assertThat(r.statusCode()).as("GET %s", path).isEqualTo(200);
            assertThat(r.body()).as("GET %s", path).contains("id=\"app\"", "./assets/");
        }
        // 静态资产真实可取
        String index = get("/netproto/").body();
        String asset = java.util.Arrays.stream(index.split("src=\""))
                .filter(s -> s.startsWith("./assets/"))
                .map(s -> s.substring(0, s.indexOf('"')))
                .findFirst().orElseThrow();
        assertThat(get("/netproto/" + asset.substring(2)).statusCode()).isEqualTo(200);
    }

    /** 宿主应用的根路径不被观测台占用(静态资源已移出 Boot 默认 static/)。 */
    @Test
    void rootNotOccupiedByUi() throws Exception {
        assertThat(get("/").statusCode()).isEqualTo(404);
        assertThat(get("/favicon.ico").statusCode()).isEqualTo(404);
    }

    /** REST 接口路径不受挂载前缀影响。 */
    @Test
    void restEndpointsUnchanged() throws Exception {
        assertThat(get("/api/netproto/config").statusCode()).isEqualTo(200);
    }

    /** 挂载路径规范化:根路径拒绝;缺省斜杠补齐;尾斜杠去除。 */
    @Test
    void basePathNormalization() {
        NetprotoProperties p = new NetprotoProperties();
        assertThat(p.normalizedUiBasePath()).isEqualTo("/netproto");   // 默认
        p.setUiBasePath("tools/");
        assertThat(p.normalizedUiBasePath()).isEqualTo("/tools");      // 补头斜杠、去尾斜杠
        p.setUiBasePath("/a/b/");
        assertThat(p.normalizedUiBasePath()).isEqualTo("/a/b");
        p.setUiBasePath("/");
        assertThrows(IllegalStateException.class, p::normalizedUiBasePath);
        p.setUiBasePath("");
        assertThrows(IllegalStateException.class, p::normalizedUiBasePath);
    }
}
