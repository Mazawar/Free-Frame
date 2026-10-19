package com.example.demo.protocol.config;

import com.example.demo.protocol.capture.CaptureEngine;
import com.example.demo.protocol.capture.RawSender;
import com.example.demo.protocol.stack.ProtocolRegistry;
import com.example.demo.protocol.stack.StackDecoder;
import com.example.demo.protocol.stack.StackEncoder;
import com.example.demo.protocol.web.NetprotoController;
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

    /** 内置协议栈所在包(ethernet/arp/ipv4/icmp/udp/tcp,与用户协议同一套注解机制)。 */
    public static final String BUILTIN_PACKAGE = "com.example.demo.protocol.builtin";

    @Bean
    public ProtocolRegistry protocolRegistry(BeanFactory beanFactory, NetprotoProperties props) {
        LinkedHashSet<String> packages = new LinkedHashSet<>();
        packages.add(BUILTIN_PACKAGE);
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
    public CaptureEngine captureEngine(StackDecoder decoder, NetprotoProperties props) {
        return new CaptureEngine(decoder, props.getRingSize(), props.getSnaplen());
    }

    @Bean
    public RawSender rawSender(StackEncoder encoder) {
        return new RawSender(encoder);
    }

    @Bean
    public NetprotoController netprotoController(ProtocolRegistry registry,
                                                 CaptureEngine captureEngine,
                                                 RawSender rawSender,
                                                 StackEncoder stackEncoder,
                                                 org.springframework.context.ApplicationContext appContext) {
        return new NetprotoController(registry, captureEngine, rawSender, stackEncoder, appContext);
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
                com.example.demo.protocol.annotation.Protocol.class));
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
            ids.add(c.getAnnotation(com.example.demo.protocol.annotation.Protocol.class).id());
        }
        return ids;
    }
}
