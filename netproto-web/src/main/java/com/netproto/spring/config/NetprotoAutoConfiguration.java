package com.netproto.spring.config;

import com.netproto.spring.capture.RawSender;
import com.netproto.spring.capture.SessionManager;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackDecoder;
import com.netproto.stack.StackEncoder;
import com.netproto.spring.web.NetprotoController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurationPackages;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 自动装配:classpath 扫描 @Protocol 类 → 构建分派树 → 装配采集/发包/Web。
 * <p>
 * 扫描范围 = 内置协议栈包(永远注册)∪ netproto.base-packages(默认主应用包)。
 * 重复 id / 未知父 / 非法 when 等校验失败 → 应用启动失败(fail-fast)。
 */
@AutoConfiguration
@EnableConfigurationProperties(NetprotoProperties.class)
@ConditionalOnProperty(prefix = "netproto", name = "enabled", havingValue = "true", matchIfMissing = true)
public class NetprotoAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(NetprotoAutoConfiguration.class);

    @Bean
    public ProtocolRegistry protocolRegistry(BeanFactory beanFactory, NetprotoProperties props) {
        LinkedHashSet<String> packages = new LinkedHashSet<>();
        packages.addAll(props.getBuiltinPackages());   // 内置栈(netproto-protocols 可选,扫不到即空)
        packages.addAll(resolveUserPackages(beanFactory, props));
        List<Class<?>> classes = scanProtocols(packages);
        log.info("netproto: registering {} protocol classes from {}: {}",
                classes.size(), packages, classIds(classes));
        return ProtocolRegistry.create(classes);
    }

    @Bean
    public StackDecoder stackDecoder(ProtocolRegistry registry, NetprotoProperties props) {
        return new StackDecoder(registry, props.getRootProtocol());
    }

    @Bean
    public StackEncoder stackEncoder(ProtocolRegistry registry) {
        return new StackEncoder(registry);
    }

    @Bean
    public SessionManager sessionManager(StackDecoder decoder, NetprotoProperties props) {
        return new SessionManager(decoder, props.getRingSize(),
                (int) props.getRingBytes().toBytes(), props.getSnaplen(), props.getMaxSessions());
    }

    @Bean
    public RawSender rawSender(StackEncoder encoder) {
        return new RawSender(encoder);
    }

    @Bean
    public com.netproto.spring.capture.BpfValidator bpfValidator() {
        return new com.netproto.spring.capture.BpfValidator();
    }

    /** API 令牌过滤器(netproto.auth-token 非空时启用;默认不拦截,demo 本机用法)。 */
    @Bean
    public org.springframework.boot.web.servlet.FilterRegistrationBean<com.netproto.spring.web.NetprotoAuthFilter>
    netprotoAuthFilter(NetprotoProperties props) {
        var reg = new org.springframework.boot.web.servlet.FilterRegistrationBean<>(
                new com.netproto.spring.web.NetprotoAuthFilter(props));
        reg.addUrlPatterns("/api/netproto/*");
        reg.setOrder(org.springframework.core.Ordered.HIGHEST_PRECEDENCE + 10);
        return reg;
    }

    @Bean
    public NetprotoController netprotoController(ProtocolRegistry registry,
                                                 SessionManager sessionManager,
                                                 RawSender rawSender,
                                                 StackEncoder stackEncoder,
                                                 NetprotoProperties props,
                                                 com.netproto.spring.capture.BpfValidator bpfValidator,
                                                 org.springframework.context.ApplicationContext appContext) {
        return new NetprotoController(registry, sessionManager, rawSender, stackEncoder, appContext,
                props, bpfValidator);
    }

    /**
     * 观测台静态页挂载在专属路径(netproto.ui-base-path,默认 /netproto)。
     * 页面资源放在独立的 classpath:/netproto-ui/ 目录、只经本 handler 暴露,
     * 不进 Spring Boot 默认的 static/ —— starter 嵌入宿主工程时不占宿主根路径。
     */
    @Bean
    public org.springframework.web.servlet.config.annotation.WebMvcConfigurer netprotoUiMount(
            NetprotoProperties props) {
        return new org.springframework.web.servlet.config.annotation.WebMvcConfigurer() {
            @Override
            public void addResourceHandlers(
                    org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry registry) {
                String base = props.normalizedUiBasePath();
                registry.addResourceHandler(base + "/**")
                        .addResourceLocations("classpath:/netproto-ui/");
                log.info("netproto: observatory UI mounted at {} (REST stays at /api/netproto/**)", base);
            }
        };
    }

    /** 裸挂载路径转发到 index.html(/netproto 与 /netproto/ 都直达观测台)。
     *  作为 @Configuration 嵌套 @Component 由 Spring 自动注册,无需再声明 @Bean。 */
    @org.springframework.web.bind.annotation.RestController
    public static class UiForwardController {
        private final NetprotoProperties props;

        public UiForwardController(NetprotoProperties props) {
            this.props = props;
        }

        @org.springframework.web.bind.annotation.GetMapping({
                "${netproto.ui-base-path:/netproto}",
                "${netproto.ui-base-path:/netproto}/"
        })
        public org.springframework.web.servlet.ModelAndView forwardIndex() {
            return new org.springframework.web.servlet.ModelAndView(
                    "forward:" + props.normalizedUiBasePath() + "/index.html");
        }
    }

    // ---- 扫描 ----

    private static List<String> resolveUserPackages(BeanFactory beanFactory, NetprotoProperties props) {
        if (!props.getBasePackages().isEmpty()) {
            return props.getBasePackages();
        }
        try {
            return new ArrayList<>(AutoConfigurationPackages.get(beanFactory));
        } catch (IllegalStateException e) {
            log.warn("netproto: no auto-configuration packages available, scanning builtins only");
            return List.of();
        }
    }

    private static List<Class<?>> scanProtocols(Set<String> packages) {
        ClassPathScanningCandidateComponentProvider scanner =
                new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(
                com.netproto.annotation.Protocol.class));
        List<Class<?>> out = new ArrayList<>();
        for (String pkg : packages) {
            scanner.findCandidateComponents(pkg).forEach(bd -> {
                try {
                    out.add(Class.forName(bd.getBeanClassName()));
                } catch (ClassNotFoundException e) {
                    throw new IllegalStateException("cannot load scanned @Protocol class", e);
                }
            });
        }
        return out;
    }

    private static List<String> classIds(List<Class<?>> classes) {
        List<String> ids = new ArrayList<>();
        for (Class<?> c : classes) {
            ids.add(c.getAnnotation(com.netproto.annotation.Protocol.class).id());
        }
        return ids;
    }
}
