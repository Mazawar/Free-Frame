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

    /** 采集环形缓冲帧数上限。默认 10 万:真正限制驻留量的是 {@link #ringBytes} 字节预算
     *  (16MB ≈ 平均帧 500B 时约 3 万帧,大帧更少)——Wireshark 同为内存约束而非行数约束。 */
    private int ringSize = 100_000;

    /** 环形缓冲字节预算(Wireshark 捕获缓冲同思路):大帧场景下按内存淘汰最旧帧,
     *  与 ringSize 帧数上限取先到者。yaml 支持友好写法,如 16MB / 512KB。 */
    private org.springframework.util.unit.DataSize ringBytes =
            org.springframework.util.unit.DataSize.ofMegabytes(16);

    /** 采集 snaplen。 */
    private int snaplen = 65536;

    /** 观测台 UI 的挂载路径(starter 嵌入宿主工程时不占用根路径)。 */
    private String uiBasePath = "/netproto";

    /** 并发采集会话上限(含 default 兼容会话)。每会话占一个 native 捕获句柄 + 两条线程,上限护资源。 */
    private int maxSessions = 4;

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

    public org.springframework.util.unit.DataSize getRingBytes() {
        return ringBytes;
    }

    public void setRingBytes(org.springframework.util.unit.DataSize ringBytes) {
        this.ringBytes = ringBytes;
    }

    public int getSnaplen() {
        return snaplen;
    }

    public void setSnaplen(int snaplen) {
        this.snaplen = snaplen;
    }

    public int getMaxSessions() {
        return maxSessions;
    }

    public void setMaxSessions(int maxSessions) {
        this.maxSessions = maxSessions;
    }

    public String getUiBasePath() {
        return uiBasePath;
    }

    public void setUiBasePath(String uiBasePath) {
        this.uiBasePath = uiBasePath;
    }

    /**
     * 规范化挂载路径:去空白、保证以 / 开头、去尾部 /。
     * 根路径 "/" 被拒绝 —— 观测台占根路径会与宿主应用冲突,这正是本属性存在的原因。
     */
    public String normalizedUiBasePath() {
        String p = uiBasePath == null ? "" : uiBasePath.trim();
        if (p.isEmpty() || p.equals("/")) {
            throw new IllegalStateException(
                    "netproto.ui-base-path 必须是根下的子路径(如 /netproto),不能为空或 \"/\""
                            + " —— 观测台不占宿主应用的根路径");
        }
        if (!p.startsWith("/")) {
            p = "/" + p;
        }
        while (p.endsWith("/") && p.length() > 1) {
            p = p.substring(0, p.length() - 1);
        }
        return p;
    }
}
