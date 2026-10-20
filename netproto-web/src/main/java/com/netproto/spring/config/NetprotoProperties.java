package com.netproto.spring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/** netproto.* 配置。 */
@ConfigurationProperties(prefix = "netproto")
public class NetprotoProperties {

    /** 总开关(false 时整个组件不装配)。 */
    private boolean enabled = true;

    /** 用户 @Protocol 协议的扫描包;为空时默认扫描主应用包。 */
    private List<String> basePackages = new ArrayList<>();

    /** 内置协议栈扫描包(默认 netproto-protocols 模块;未引入该模块时扫不到即降级为空,设空列表可禁用内置栈)。 */
    private List<String> builtinPackages = new ArrayList<>(List.of("com.netproto.protocols.builtin"));

    /** 分派树根协议 id。 */
    private String rootProtocol = "ethernet";

    /** 采集环形缓冲容量。 */
    private int ringSize = 500;

    /** 采集 snaplen。 */
    private int snaplen = 65536;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getBasePackages() {
        return basePackages;
    }

    public void setBasePackages(List<String> basePackages) {
        this.basePackages = basePackages;
    }

    public List<String> getBuiltinPackages() {
        return builtinPackages;
    }

    public void setBuiltinPackages(List<String> builtinPackages) {
        this.builtinPackages = builtinPackages;
    }

    public String getRootProtocol() {
        return rootProtocol;
    }

    public void setRootProtocol(String rootProtocol) {
        this.rootProtocol = rootProtocol;
    }

    public int getRingSize() {
        return ringSize;
    }

    public void setRingSize(int ringSize) {
        this.ringSize = ringSize;
    }

    public int getSnaplen() {
        return snaplen;
    }

    public void setSnaplen(int snaplen) {
        this.snaplen = snaplen;
    }
}
