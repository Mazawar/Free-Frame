package com.netproto.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 入口:协议注册由 NetprotoAutoConfiguration 自动完成(扫描 @Protocol),
 * 这里不再有任何手工注册代码。
 */
@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
