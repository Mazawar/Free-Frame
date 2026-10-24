package com.netproto.spring.capture;

import com.netproto.annotation.Protocol;
import com.netproto.stack.ProtocolRegistry;
import com.netproto.stack.StackDecoder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 多会话核心语义:会话间完全隔离(缓冲/序号/订阅独立)、并发上限、
 * default 懒重建与删除语义——多页面并行抓不同包不互相污染的基础。
 */
class SessionManagerTest {

    /** 用内置协议栈构建真实解码器(与自动装配同一扫描方式)。 */
    private static StackDecoder newDecoder() throws Exception {
        ClassPathScanningCandidateComponentProvider scanner =
                new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(Protocol.class));
        List<Class<?>> classes = new ArrayList<>();
        for (BeanDefinition bd : scanner.findCandidateComponents("com.netproto.protocols.builtin")) {
            classes.add(Class.forName(bd.getBeanClassName()));
        }
        return new StackDecoder(ProtocolRegistry.create(classes), "ethernet");
    }

    /** 15 字节广播以太网帧(未注册 ethertype:只解出 ethernet 层,足够验证隔离)。 */
    private static byte[] ethFrame(int tag) {
        return new byte[] {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                (byte) 0x88, (byte) 0xb2,
                (byte) tag};
    }

    @Test
    void sessionsAreIsolated() throws Exception {
        StackDecoder decoder = newDecoder();
        CaptureSession s1 = new CaptureSession("s1", decoder, 100, 64 * 1024, 65536);
        CaptureSession s2 = new CaptureSession("s2", decoder, 100, 64 * 1024, 65536);
        List<FrameSummary> got1 = new CopyOnWriteArrayList<>();
        List<FrameSummary> got2 = new CopyOnWriteArrayList<>();
        s1.addListener(got1::add);
        s2.addListener(got2::add);

        s1.inject("t1", ethFrame(1));
        s2.inject("t2", ethFrame(2));
        s2.inject("t2", ethFrame(3));

        // 缓冲隔离:各会话只见自己注入的帧
        assertEquals(1, s1.recent(10).size());
        assertEquals(2, s2.recent(10).size());
        // 序号独立:两会话各自从 1 起,多会话序号天然不撞车(recent 新→旧)
        assertEquals(1, s1.recent(10).get(0).seq());
        assertEquals(2, s2.recent(10).get(0).seq());
        // 订阅隔离:监听者只收到本会话的帧
        assertEquals(1, got1.size());
        assertEquals(2, got2.size());
        // 详情按会话命中;他会的 seq 查不到
        assertNotNull(s1.detail(1));
        assertNotNull(s2.detail(1));
        assertNull(s2.detail(3));
    }

    @Test
    void managerLimitDeleteAndDefaultRecreate() throws Exception {
        StackDecoder decoder = newDecoder();
        SessionManager mgr = new SessionManager(decoder, 100, 64 * 1024, 65536, 3) {
            @Override
            protected CaptureSession newSession(String id) {
                // 测试桩:start 不碰真实网卡
                return new CaptureSession(id, decoder, 100, 64 * 1024, 65536) {
                    @Override
                    public void start(String iface, String bpf) {
                        // no-op
                    }
                };
            }
        };

        // default 懒创建,旧端点的固定落点
        CaptureSession def1 = mgr.defaultSession();
        assertEquals("default", def1.id());
        // 上限 3(含 default):s1、s2 占满剩余名额
        assertEquals("s1", mgr.create("lo", "").id());
        assertEquals("s2", mgr.create("lo", "").id());
        IllegalStateException rejected = assertThrows(IllegalStateException.class,
                () -> mgr.create("lo", ""));
        assertTrue(rejected.getMessage().contains("limit"));
        // 删除释放名额,序号生成器延续;重复删除/未知会话返回 false
        assertTrue(mgr.delete("s1"));
        assertFalse(mgr.delete("s1"));
        assertNull(mgr.get("nope"));
        assertEquals("s3", mgr.create("lo", "").id());
        // default 删除后懒重建为新实例(default + s2 + s3 = 满,再建被拒)
        assertTrue(mgr.delete("default"));
        assertThrows(IllegalStateException.class, () -> mgr.create("lo", ""));   // 名额被 default 预留占住
        CaptureSession def2 = mgr.defaultSession();
        assertNotSame(def1, def2);
        assertEquals("default", def2.id());
    }

    @Test
    void restartReusesSameSession() throws Exception {
        StackDecoder decoder = newDecoder();
        var starts = new int[1];
        SessionManager mgr = new SessionManager(decoder, 100, 64 * 1024, 65536, 4) {
            @Override
            protected CaptureSession newSession(String id) {
                // 测试桩:不碰真实网卡,数启动次数
                return new CaptureSession(id, decoder, 100, 64 * 1024, 65536) {
                    @Override
                    public void start(String iface, String bpf) {
                        starts[0]++;
                    }
                };
            }
        };
        CaptureSession created = mgr.create("lo", "");
        assertEquals("s1", created.id());
        assertEquals(1, starts[0]);
        // 重启 = 同一会话对象再次 start(页面稳定会话:启停是会话内操作,id 不变)
        CaptureSession restarted = mgr.restart("s1", "eth0", "arp");
        assertSame(created, restarted);
        assertEquals(2, starts[0]);
        assertNull(mgr.restart("nope", "lo", ""));
    }

    @Test
    void registerWithClientGeneratedId() throws Exception {
        StackDecoder decoder = newDecoder();
        var starts = new int[1];
        SessionManager mgr = new SessionManager(decoder, 100, 64 * 1024, 65536, 4) {
            @Override
            protected CaptureSession newSession(String id) {
                // 测试桩:不碰真实网卡,数启动次数
                return new CaptureSession(id, decoder, 100, 64 * 1024, 65536) {
                    @Override
                    public void start(String iface, String bpf) {
                        starts[0]++;
                    }
                };
            }
        };
        // 页面生成的 UUID 形态 id:注册即以该 id 创建
        String id = "3f2a1b8e-9c2d-4a17-8f6b-2c31d5e7a9b4";
        CaptureSession s = mgr.register(id, "lo", "");
        assertEquals(id, s.id());
        assertEquals(1, starts[0]);
        // 后端重启/回收后凭同一 id 再注册 = 同一会话对象重启(身份永不换)
        assertSame(s, mgr.register(id, "lo", ""));
        assertEquals(2, starts[0]);
        // 保留字与非法 id 拒绝(→400)
        assertThrows(IllegalArgumentException.class, () -> mgr.register("default", "lo", ""));
        assertThrows(IllegalArgumentException.class, () -> mgr.register("bad id!", "lo", ""));
        assertThrows(IllegalArgumentException.class, () -> mgr.register("ab", "lo", ""));
    }

    @Test
    void idleRegisterCreatesWithoutStarting() throws Exception {
        StackDecoder decoder = newDecoder();
        var starts = new int[1];
        SessionManager mgr = new SessionManager(decoder, 100, 64 * 1024, 65536, 4) {
            @Override
            protected CaptureSession newSession(String id) {
                return new CaptureSession(id, decoder, 100, 64 * 1024, 65536) {
                    @Override
                    public void start(String iface, String bpf) {
                        starts[0]++;
                    }
                };
            }
        };
        // 空闲注册(页面加载即占位):不启动采集;重复注册幂等返回同一对象
        CaptureSession s = mgr.registerIdle("page-uuid-1234");
        assertNotNull(s);
        assertFalse(s.isRunning());
        assertEquals(0, starts[0]);
        assertSame(s, mgr.registerIdle("page-uuid-1234"));
        // 之后带网卡注册 = 启动采集(同一会话)
        mgr.register("page-uuid-1234", "lo", "");
        assertEquals(1, starts[0]);
        // id 规则同 register
        assertThrows(IllegalArgumentException.class, () -> mgr.registerIdle("default"));
        assertThrows(IllegalArgumentException.class, () -> mgr.registerIdle("bad id"));
    }

    @Test
    void shutdownClosesAllSessions() throws Exception {
        StackDecoder decoder = newDecoder();
        var closed = new CopyOnWriteArrayList<String>();
        SessionManager mgr = new SessionManager(decoder, 100, 64 * 1024, 65536, 4, 0) {
            @Override
            protected CaptureSession newSession(String id) {
                // 测试桩:start 不碰真实网卡;close 记录调用(运行中关停 JVM 必须cleanup全部会话)
                return new CaptureSession(id, decoder, 100, 64 * 1024, 65536) {
                    @Override
                    public void start(String iface, String bpf) {
                        // no-op
                    }
                    @Override
                    public void close() {
                        closed.add(id);
                        super.close();
                    }
                };
            }
        };
        mgr.defaultSession();
        mgr.create("lo", "");
        mgr.shutdown();
        assertTrue(closed.contains("default"), "shutdown 必须关停 default(否则非守护线程使 JVM 退不出)");
        assertTrue(closed.contains("s1"));
        assertNull(mgr.get("default"));
        assertNull(mgr.get("s1"));
    }

    @Test
    void idleSessionsWithoutViewersAreReaped() throws Exception {
        StackDecoder decoder = newDecoder();
        // grace=200ms:手动调 sweepIdleSessions 验证回收规则(定时器也会跑,不影响断言)
        SessionManager mgr = new SessionManager(decoder, 100, 64 * 1024, 65536, 4, 200) {
            @Override
            protected CaptureSession newSession(String id) {
                // 测试桩:start 不碰真实网卡
                return new CaptureSession(id, decoder, 100, 64 * 1024, 65536) {
                    @Override
                    public void start(String iface, String bpf) {
                        // no-op
                    }
                };
            }
        };
        CaptureSession orphan = mgr.create("lo", "");            // 无订阅者:页面已关
        CaptureSession watched = mgr.create("lo", "");
        var sink = new java.util.ArrayList<FrameSummary>();
        watched.addListener(sink::add);                          // 有订阅者:页面开着
        Thread.sleep(300);
        mgr.sweepIdleSessions();
        assertNull(mgr.get(orphan.id()), "无订阅者超宽限:应被回收");
        assertNotNull(mgr.get(watched.id()), "有订阅者:不回收");
        // default 豁免:curl 等传统用法常无订阅者
        mgr.defaultSession();
        Thread.sleep(300);
        mgr.sweepIdleSessions();
        assertNotNull(mgr.get(SessionManager.DEFAULT_ID), "default 不参与空闲回收");
    }
}
