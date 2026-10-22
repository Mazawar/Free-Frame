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

/** 自定义挂载路径:netproto.ui-base-path 可改,默认路径随之失效。 */
@SpringBootTest(classes = UiCustomBasePathTest.App.class,
        properties = "netproto.ui-base-path=/tools",
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UiCustomBasePathTest {

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
    void uiServedAtCustomBasePath() throws Exception {
        for (String path : new String[]{"/tools", "/tools/"}) {
            HttpResponse<String> r = get(path);
            assertThat(r.statusCode()).as("GET %s", path).isEqualTo(200);
            assertThat(r.body()).as("GET %s", path).contains("id=\"app\"");
        }
        // 默认路径不再挂载
        assertThat(get("/netproto/").statusCode()).isEqualTo(404);
    }
}
