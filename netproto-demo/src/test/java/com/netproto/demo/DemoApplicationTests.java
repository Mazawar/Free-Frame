package com.netproto.demo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 上下文冒烟:扫描范围收窄到内置协议栈包,避免把 test-classpath 上的
 * codec 校验夹具(带 @Protocol 的内部类)卷进注册表。
 * 用户协议扫描的完整行为由 AutoConfigTest 验证。
 */
@SpringBootTest(properties = "netproto.base-packages=com.netproto.protocols.builtin")
class DemoApplicationTests {

    @Test
    void contextLoads() {
    }

}
