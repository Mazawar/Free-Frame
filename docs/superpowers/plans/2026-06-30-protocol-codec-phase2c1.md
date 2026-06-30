# 通用协议编解码引擎 Phase 2c1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给引擎加上异质 TLV 支持——标准 TLV(type+length 各1字节 + value)按 type 分派到不同 value 实体,sentinel 终止,未知 type 跳过。做完能解析 DHCP Options。

**Architecture:** 新增 `FieldType.LIST_TLV` + `@ProtocolField.tlvEndMarker` + `@ProtocolField.dispatch`(type→类名字符串数组)。LIST_TLV 是全新分支(不碰现有 LIST/sentinel/count 路径),在 `readValue`/`writeValue` 的 switch 之前加守卫(同 sentinel/LIST 模式)。value 实体只含 value 部分,外壳 type/length 由引擎统一读写。序列化用 dispatch 的反向 Map(类→type)。

**Tech Stack:** Java 25,Spring Boot 4.1,JUnit Jupiter 6 + AssertJ 3.27,Lombok。

**参考 spec:** `docs/superpowers/specs/2026-06-30-protocol-codec-phase2c1-design.md`

**测试约定:** `./mvnw test -Dtest=XxxTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`(单类);全量 `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`。Git Bash on Windows。

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `core/FieldType.java` | 加 `LIST_TLV` 枚举值 | 修改 |
| `annotation/ProtocolField.java` | 加 `tlvEndMarker`/`dispatch` 属性 | 修改 |
| `core/ProtocolCodec.java` | FieldInfo 读新属性 + dispatch 解析/反向Map + LIST_TLV 分支(反/序列化+resolveSize+注册校验) | 修改 |
| `protocol/dhcp/SubnetMask.java` | TLV value 实体(4字节IP) | 新建 |
| `protocol/dhcp/Router.java` | TLV value 实体(4字节IP) | 新建 |
| `protocol/dhcp/DhcpMsgType.java` | TLV value 实体(1字节) | 新建 |
| `protocol/dhcp/DhcpOptions.java` | 含 LIST_TLV 字段的顶层实体 | 新建 |
| `test/.../TlvBasicTest.java` | 已知 type round-trip | 新建 |
| `test/.../TlvUnknownTypeTest.java` | 未知 type 跳过 | 新建 |
| `test/.../TlvSentinelTest.java` | sentinel 终止 | 新建 |
| `test/.../TlvValidationTest.java` | dispatch 校验 | 新建 |

包路径:DHC P 实体放 `com.example.demo.protocol.dhcp` 子包。所有测试为纯 JUnit。

---

## Task 1: FieldType 加 LIST_TLV + 注解属性

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/FieldType.java`
- Modify: `src/main/java/com/example/demo/protocol/annotation/ProtocolField.java`

- [ ] **Step 1: FieldType 加 LIST_TLV**

在 `FieldType.java` 的 `LIST` 之后加:
```java
    /** count 驱动的同质重复数组:元素是 elementClass 实体,个数由 countField 决定。 */
    LIST,
    /** 异质 TLV:每个元素 type+length+value,type 决定 value 实体类(dispatch 分派)。 */
    LIST_TLV
}
```

- [ ] **Step 2: ProtocolField 加 tlvEndMarker / dispatch**

在 `ProtocolField.java` 的 `flagClass()` 之后加两个属性:
```java
    /** 位标志字段:字段类型为 Set,用此指定具体 flag enum 类。 */
    Class<?> flagClass() default void.class;

    /** 异质 TLV 的 sentinel:type == 此值就结束(0x00–0xFF);-1 表示不用(读到末尾停)。 */
    int tlvEndMarker() default -1;

    /** 异质 TLV 分派表:type→value 实体类名,格式 {"1=SubnetMask", "3=Router"}。
     *  类名为简单名时按字段声明类所在包解析;也支持全限定名。 */
    String[] dispatch() default {};
```

- [ ] **Step 3: 编译确认**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD FAILURE` —— `readValue`/`writeValue` 的 switch 表达式/语句不穷尽(LIST_TLV 无 case)。**这是预期的**,Task 3 会补 case。但为让本任务编译通过,先在 `readValue` 的 switch 表达式加临时 stub(同 Phase 2a Task 1 的做法):

在 `readValue` 的 switch 表达式里加(与 sentinel 守卫之后、`FieldType type = effectiveType(fi)` 之后的 switch):
```java
            case LIST_TLV -> throw new UnsupportedOperationException("FieldType.LIST_TLV not yet supported");
```

`writeValue` 是 switch 语句(不要求穷尽),暂不加。

再编译:Expected: `BUILD SUCCESS`

- [ ] **Step 4: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/FieldType.java src/main/java/com/example/demo/protocol/annotation/ProtocolField.java src/main/java/com/example/demo/protocol/core/ProtocolCodec.java
git commit -m "feat(codec): add LIST_TLV enum and tlvEndMarker/dispatch annotation attrs"
```

---

## Task 2: DHCP value 实体 + DhcpOptions

**Files:**
- Create: `src/main/java/com/example/demo/protocol/dhcp/SubnetMask.java`
- Create: `src/main/java/com/example/demo/protocol/dhcp/Router.java`
- Create: `src/main/java/com/example/demo/protocol/dhcp/DhcpMsgType.java`
- Create: `src/main/java/com/example/demo/protocol/dhcp/DhcpOptions.java`

- [ ] **Step 1: 创建 dhcp 子包的 4 个实体**

`SubnetMask.java`:
```java
package com.example.demo.protocol.dhcp;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import lombok.Data;
import lombok.ToString;

/** DHCP Option 1:子网掩码(4 字节 IP)。value 实体,只含 value 部分。 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class SubnetMask {
    @ProtocolField(order = 1, size = 32)
    private int mask;
}
```

`Router.java`:
```java
package com.example.demo.protocol.dhcp;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import lombok.Data;
import lombok.ToString;

/** DHCP Option 3:路由器(4 字节 IP)。value 实体。 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class Router {
    @ProtocolField(order = 1, size = 32)
    private int address;
}
```

`DhcpMsgType.java`:
```java
package com.example.demo.protocol.dhcp;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import lombok.Data;
import lombok.ToString;

/** DHCP Option 53:消息类型(1 字节)。value 实体。 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DhcpMsgType {
    @ProtocolField(order = 1, size = 8)
    private int type;
}
```

`DhcpOptions.java`:
```java
package com.example.demo.protocol.dhcp;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import lombok.Data;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/** DHCP Options 段:异质 TLV,type=0xFF 结束。 */
@Data
@ToString
@ProtocolPacket(port = 0)
public class DhcpOptions {

    @ProtocolField(order = 1, type = FieldType.LIST_TLV,
            tlvEndMarker = 0xFF,
            dispatch = {"1=SubnetMask", "3=Router", "53=DhcpMsgType"})
    private List<Object> options = new ArrayList<>();
}
```

- [ ] **Step 2: 编译确认(实体本身能编译;LIST_TLV 编解码在 Task 3 实现)**

Run: `./mvnw compile 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 提交**

```bash
git add src/main/java/com/example/demo/protocol/dhcp/
git commit -m "feat(protocol): add DHCP TLV value entities and DhcpOptions"
```

---

## Task 3: ProtocolCodec LIST_TLV 分支(核心)

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`

这是 Phase 2c1 核心。涉及:FieldInfo 读新属性 + dispatch 解析(正向 Map + 反向 Map)+ resolveSize + readValue + writeValue + 注册校验。

- [ ] **Step 1: 写失败测试**

创建 `src/test/java/com/example/demo/protocol/TlvBasicTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.dhcp.DhcpMsgType;
import com.example.demo.protocol.dhcp.DhcpOptions;
import com.example.demo.protocol.dhcp.Router;
import com.example.demo.protocol.dhcp.SubnetMask;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TlvBasicTest {

    @Test
    void roundTripsKnownTlvTypes() {
        new ProtocolCodec<>(SubnetMask.class);
        new ProtocolCodec<>(Router.class);
        new ProtocolCodec<>(DhcpMsgType.class);
        ProtocolCodec<DhcpOptions> codec = new ProtocolCodec<>(DhcpOptions.class);

        DhcpOptions opts = new DhcpOptions();
        SubnetMask sm = new SubnetMask();
        sm.setMask(0xC0A80101);       // 192.168.1.1
        Router r = new Router();
        r.setAddress(0xC0A801FE);      // 192.168.1.254
        DhcpMsgType mt = new DhcpMsgType();
        mt.setType(2);                  // OFFER
        opts.getOptions().add(sm);
        opts.getOptions().add(r);
        opts.getOptions().add(mt);

        byte[] out = codec.serialize(opts);
        // 01 04 C0A80101 | 03 04 C0A801FE | 35 01 02 | FF
        assertThat(out).containsExactly(
                0x01, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, 0x01,
                0x03, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, (byte) 0xFE,
                0x35, 0x01, 0x02,
                (byte) 0xFF);

        DhcpOptions parsed = codec.deserialize(out);
        assertThat(parsed.getOptions()).hasSize(3);
        assertThat(parsed.getOptions().get(0)).isInstanceOf(SubnetMask.class);
        assertThat(((SubnetMask) parsed.getOptions().get(0)).getMask()).isEqualTo(0xC0A80101);
        assertThat(parsed.getOptions().get(1)).isInstanceOf(Router.class);
        assertThat(((Router) parsed.getOptions().get(1)).getAddress()).isEqualTo(0xC0A801FE);
        assertThat(parsed.getOptions().get(2)).isInstanceOf(DhcpMsgType.class);
        assertThat(((DhcpMsgType) parsed.getOptions().get(2)).getType()).isEqualTo(2);
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `./mvnw test -Dtest=TlvBasicTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(LIST_TLV stub 抛 UnsupportedOperationException)

- [ ] **Step 3: FieldInfo 加新字段 + dispatch 解析**

在 `FieldInfo` 内部类加字段:`final int tlvEndMarker;`、`final String[] dispatch;`、`final java.util.Map<Integer,String> dispatchMap;`(type→类名)、`final java.util.Map<String,Integer> reverseDispatchMap;`(类名→type)。

在 `FieldInfo(Field f)` 构造器里:
```java
            this.tlvEndMarker = ann.tlvEndMarker();
            this.dispatch = ann.dispatch();
            // 解析 dispatch 为正/反向 Map
            // 正向:type → 类名字符串(反序列化用 resolveDispatchClass 加载)
            // 反向:类简单名 → type(序列化用 elem.getClass().getSimpleName() 反查)
            java.util.Map<Integer,String> fwd = new java.util.HashMap<>();
            java.util.Map<String,Integer> rev = new java.util.HashMap<>();
            for (String entry : this.dispatch) {
                int eq = entry.indexOf('=');
                if (eq < 0) throw new IllegalArgumentException("dispatch entry must be 'type=ClassName': " + entry);
                int t = Integer.parseInt(entry.substring(0, eq).trim());
                String cn = entry.substring(eq + 1).trim();
                if (fwd.containsKey(t)) throw new IllegalArgumentException("dispatch type " + t + " duplicated");
                fwd.put(t, cn);
                // 反向 key 用简单名(去掉包前缀),与 elem.getClass().getSimpleName() 对齐
                String simple = cn.contains(".") ? cn.substring(cn.lastIndexOf('.') + 1) : cn;
                rev.put(simple, t);
            }
            this.dispatchMap = fwd;
            this.reverseDispatchMap = rev;
```

在私有 `FieldInfo(Field f, String name)`(@Payload)构造器里:
```java
            this.tlvEndMarker = -1;
            this.dispatch = new String[0];
            this.dispatchMap = java.util.Collections.emptyMap();
            this.reverseDispatchMap = java.util.Collections.emptyMap();
```

- [ ] **Step 4: 类名解析辅助方法**

在 ProtocolCodec 类中加一个辅助方法(解析简单名/全限定名为 Class):
```java
    /** 解析 dispatch 类名:简单名按 declaringClass 所在包,全限定名直接加载。 */
    private static Class<?> resolveDispatchClass(String className, Class<?> contextClass) {
        if (className.contains(".")) {
            try { return Class.forName(className); } catch (ClassNotFoundException e) {
                throw new IllegalArgumentException("dispatch class not found: " + className, e);
            }
        }
        String pkg = contextClass.getPackageName();
        String fqn = pkg.isEmpty() ? className : pkg + "." + className;
        try { return Class.forName(fqn); } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("dispatch class not found: " + className + " (resolved " + fqn + ")", e);
        }
    }
```

- [ ] **Step 5: resolveSize 加 LIST_TLV 分支(序列化算总位数)**

在 `resolveSize` 最前面(sentinel 分支之前)加:
```java
        // -2. LIST_TLV:总位数 = 各元素(type 1B + length 1B + value)累加 + (endMarker 则 +8)
        if (effectiveType(fi) == FieldType.LIST_TLV) {
            return tlvTotalBits(fi, obj);
        }
```

并新增私有方法 `tlvTotalBits`(放在 `listTotalBits` 附近):
```java
    /** 计算 LIST_TLV 字段总位数(供 resolveSize 序列化用)。 */
    private long tlvTotalBits(FieldInfo fi, Object obj) throws Exception {
        fi.field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.List<Object> list = (java.util.List<Object>) fi.field.get(obj);
        long total = 0;
        Class<?> contextClass = fi.field.getDeclaringClass();
        for (Object elem : list) {
            // type(8) + length(8) + value
            byte[] valueBytes = serializeNested(codecFor(elem.getClass()), elem);
            total += 8 + 8 + valueBytes.length * 8L;
        }
        if (fi.tlvEndMarker >= 0) {
            total += 8;  // sentinel 字节
        }
        return total;
    }
```

- [ ] **Step 6: readValue 替换 LIST_TLV stub 为真逻辑**

把 `readValue` 的 `case LIST_TLV -> throw ...` 替换为:
```java
            case LIST_TLV -> {
                yield readTlvValue(fi, cursor);
            }
```

并新增私有方法 `readTlvValue`:
```java
    /** LIST_TLV 反序列化:循环读 type+length+value,sentinel 终止,未知 type 跳过。 */
    private Object readTlvValue(FieldInfo fi, BitCursor cursor) throws Exception {
        Class<?> contextClass = fi.field.getDeclaringClass();
        java.util.List<Object> list = new java.util.ArrayList<>();
        while (true) {
            int peek = cursor.peekByte();
            if (peek < 0) break;  // 到末尾
            if (fi.tlvEndMarker >= 0 && peek == fi.tlvEndMarker) {
                cursor.skipBits(8);  // 消费 sentinel
                break;
            }
            int type = (int) cursor.readBits(8);
            int length = (int) cursor.readBits(8);
            String className = fi.dispatchMap.get(type);
            if (className == null) {
                // 未知 type:跳过 length 字节
                cursor.skipBits(length * 8);
                continue;
            }
            Class<?> elemClass = resolveDispatchClass(className, contextClass);
            byte[] valueBytes = cursor.readBytes(length * 8);
            Object elem = codecFor(elemClass).deserialize(valueBytes, 0, valueBytes.length);
            list.add(elem);
        }
        return list;
    }
```

- [ ] **Step 7: writeValue 加 LIST_TLV 分支**

在 `writeValue` 的 sentinel 守卫之后、`FieldType type = effectiveType(fi)` 之前,加 LIST_TLV 守卫:
```java
        // LIST_TLV 序列化:每个元素 type+length+value,末尾 sentinel
        if (effectiveType(fi) == FieldType.LIST_TLV) {
            writeTlvValue(fi, obj, cursor);
            return;
        }
```

并新增私有方法 `writeTlvValue`:
```java
    /** LIST_TLV 序列化:每个元素 type+length+value,末尾追加 sentinel。 */
    @SuppressWarnings("unchecked")
    private void writeTlvValue(FieldInfo fi, Object obj, BitCursor cursor) throws Exception {
        fi.field.setAccessible(true);
        java.util.List<Object> list = (java.util.List<Object>) fi.field.get(obj);
        for (Object elem : list) {
            Integer type = fi.reverseDispatchMap.get(elem.getClass().getSimpleName());
            if (type == null) {
                throw new IllegalStateException(
                        "TLV element " + elem.getClass().getName() + " not in dispatch table");
            }
            byte[] valueBytes = serializeNested(codecFor(elem.getClass()), elem);
            cursor.writeBits(type, 8);
            cursor.writeBits(valueBytes.length, 8);
            cursor.writeBytes(valueBytes);
        }
        if (fi.tlvEndMarker >= 0) {
            cursor.writeBits(fi.tlvEndMarker, 8);
        }
    }
```

> 注:reverseDispatchMap 用**简单名**作 key,序列化时 `elem.getClass().getSimpleName()` 反查。

- [ ] **Step 8: 运行测试确认通过**

Run: `./mvnw test -Dtest=TlvBasicTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 1, Failures: 0`

- [ ] **Step 9: 全量回归(确认 Phase 1~2e 未破)**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 47 + 新 1 = 48)

- [ ] **Step 10: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/TlvBasicTest.java
git commit -m "feat(codec): implement LIST_TLV branch (dispatch + sentinel + skip unknown)"
```

---

## Task 4: 未知 type 跳过 + sentinel 测试

**Files:**
- Test: `src/test/java/com/example/demo/protocol/TlvUnknownTypeTest.java`
- Test: `src/test/java/com/example/demo/protocol/TlvSentinelTest.java`

- [ ] **Step 1: 写未知 type 测试**

创建 `src/test/java/com/example/demo/protocol/TlvUnknownTypeTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.dhcp.DhcpMsgType;
import com.example.demo.protocol.dhcp.DhcpOptions;
import com.example.demo.protocol.dhcp.Router;
import com.example.demo.protocol.dhcp.SubnetMask;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TlvUnknownTypeTest {

    @Test
    void unknownTypeIsSkipped() {
        new ProtocolCodec<>(SubnetMask.class);
        new ProtocolCodec<>(Router.class);
        new ProtocolCodec<>(DhcpMsgType.class);
        ProtocolCodec<DhcpOptions> codec = new ProtocolCodec<>(DhcpOptions.class);

        // 手构字节:SubnetMask(01 04 C0A80101) + 未知 type 99(63 01 AB) + Router(03 04 C0A801FE) + FF
        byte[] data = {
                0x01, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, 0x01,   // SubnetMask 192.168.1.1
                0x63, 0x01, (byte) 0xAB,                            // type=99(未知) len=1 value=AB → 跳过
                0x03, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, (byte) 0xFE,  // Router
                (byte) 0xFF                                         // End
        };

        DhcpOptions parsed = codec.deserialize(data);
        // 未知 type 99 被跳过,只剩 SubnetMask + Router
        assertThat(parsed.getOptions()).hasSize(2);
        assertThat(parsed.getOptions().get(0)).isInstanceOf(SubnetMask.class);
        assertThat(parsed.getOptions().get(1)).isInstanceOf(Router.class);
    }
}
```

- [ ] **Step 2: 写 sentinel 测试**

创建 `src/test/java/com/example/demo/protocol/TlvSentinelTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.core.ProtocolCodec;
import com.example.demo.protocol.dhcp.DhcpMsgType;
import com.example.demo.protocol.dhcp.DhcpOptions;
import com.example.demo.protocol.dhcp.Router;
import com.example.demo.protocol.dhcp.SubnetMask;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TlvSentinelTest {

    @Test
    void sentinelStopsParsing() {
        new ProtocolCodec<>(SubnetMask.class);
        new ProtocolCodec<>(Router.class);
        new ProtocolCodec<>(DhcpMsgType.class);
        ProtocolCodec<DhcpOptions> codec = new ProtocolCodec<>(DhcpOptions.class);

        // SubnetMask + FF(立即 sentinel)→ 只有 1 个元素
        byte[] data = {
                0x01, 0x04, (byte) 0xC0, (byte) 0xA8, 0x01, 0x01,
                (byte) 0xFF
        };
        DhcpOptions parsed = codec.deserialize(data);
        assertThat(parsed.getOptions()).hasSize(1);
        assertThat(parsed.getOptions().get(0)).isInstanceOf(SubnetMask.class);

        // round-trip:序列化回去应含 sentinel
        byte[] reserialized = codec.serialize(parsed);
        assertThat(reserialized[reserialized.length - 1]).isEqualTo((byte) 0xFF);
    }

    @Test
    void emptyTlvWithOnlySentinel() {
        new ProtocolCodec<>(SubnetMask.class);
        ProtocolCodec<DhcpOptions> codec = new ProtocolCodec<>(DhcpOptions.class);

        // 仅 FF → 空列表
        DhcpOptions parsed = codec.deserialize(new byte[]{(byte) 0xFF});
        assertThat(parsed.getOptions()).isEmpty();

        // 空列表序列化 → 仅 FF
        byte[] out = codec.serialize(new DhcpOptions());
        assertThat(out).containsExactly((byte) 0xFF);
    }
}
```

- [ ] **Step 3: 运行两个测试**

Run: `./mvnw test -Dtest="TlvUnknownTypeTest,TlvSentinelTest" 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: `Tests run: 3, Failures: 0`(未知 1 + sentinel 2)

- [ ] **Step 4: 提交**

```bash
git add src/test/java/com/example/demo/protocol/TlvUnknownTypeTest.java src/test/java/com/example/demo/protocol/TlvSentinelTest.java
git commit -m "test(codec): TLV unknown-type skip and sentinel termination"
```

---

## Task 5: 注册期 dispatch 校验

**Files:**
- Modify: `src/main/java/com/example/demo/protocol/core/ProtocolCodec.java`
- Test: `src/test/java/com/example/demo/protocol/TlvValidationTest.java`

- [ ] **Step 1: 写失败测试**

创建 `src/test/java/com/example/demo/protocol/TlvValidationTest.java`:
```java
package com.example.demo.protocol;

import com.example.demo.protocol.annotation.ProtocolField;
import com.example.demo.protocol.annotation.ProtocolPacket;
import com.example.demo.protocol.core.FieldType;
import com.example.demo.protocol.core.ProtocolCodec;
import lombok.Data;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TlvValidationTest {

    /** dispatch 类名不存在 → 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BadClassContainer {
        @ProtocolField(order = 1, type = FieldType.LIST_TLV,
                tlvEndMarker = 0xFF,
                dispatch = {"1=NonExistentClass"})
        private List<Object> options;
    }

    @Test
    void rejectsUnknownDispatchClass() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BadClassContainer.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("NonExistentClass");
    }

    /** dispatch 格式错(无 =)→ 非法。 */
    @Data
    @ProtocolPacket(port = 0)
    public static class BadFormatContainer {
        @ProtocolField(order = 1, type = FieldType.LIST_TLV,
                tlvEndMarker = 0xFF,
                dispatch = {"1SubnetMask"})
        private List<Object> options;
    }

    @Test
    void rejectsBadDispatchFormat() {
        assertThatThrownBy(() -> new ProtocolCodec<>(BadFormatContainer.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("type=ClassName");
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `./mvnw test -Dtest=TlvValidationTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: 失败(FieldInfo 构造器解析 dispatch 时已校验格式——BadFormat 可能已抛;但 BadClass 的类存在性校验需在构造期主动 resolveDispatchClass)

- [ ] **Step 3: 构造期校验 dispatch 类存在**

在 `FieldInfo(Field f)` 构造器里,解析完 dispatch Map 后,加类存在性校验(需 contextClass,即字段声明类):
```java
            // 校验:dispatch 类必须存在且是 @ProtocolPacket 实体
            Class<?> ctx = f.getDeclaringClass();
            for (String cn : fwd.values()) {
                Class<?> c = resolveDispatchClass(cn, ctx);
                if (!c.isAnnotationPresent(com.example.demo.protocol.annotation.ProtocolPacket.class)) {
                    throw new IllegalArgumentException(
                            "dispatch class " + cn + " is not a @ProtocolPacket entity");
                }
            }
```

> 注:`resolveDispatchClass` 是 static 方法,可从 FieldInfo 构造器调用。格式校验(无 '=')已在解析时抛。

- [ ] **Step 4: 运行确认通过**

Run: `./mvnw test -Dtest=TlvValidationTest 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run"`
Expected: `Tests run: 2, Failures: 0`

- [ ] **Step 5: 全量回归**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 48 + 新 2 = 50;TlvUnknown/Sentinel 也应已算入——视实际累计)。确认 DhcpOptions 仍能构造(其 dispatch 类都合法)。

- [ ] **Step 6: 提交**

```bash
git add src/main/java/com/example/demo/protocol/core/ProtocolCodec.java src/test/java/com/example/demo/protocol/TlvValidationTest.java
git commit -m "feat(codec): validate TLV dispatch class existence at registration"
```

---

## Task 6: 全量验证 + 文档更新

- [ ] **Step 1: 全量测试**

Run: `./mvnw test 2>&1 | tr -cd '\11\12\15\40-\176' | grep "Tests run" | tail -1`
Expected: 全绿(原 47 + TlvBasic 1 + TlvUnknown 1 + TlvSentinel 2 + TlvValidation 2 = 53)

- [ ] **Step 2: 全量编译打包**

Run: `./mvnw package 2>&1 | tr -cd '\11\12\15\40-\176' | grep "BUILD"`
Expected: `BUILD SUCCESS`

- [ ] **Step 3: 更新 README**

在 `README.md` 的「### Phase 2e」之后加一节「### Phase 2c1」,并把「### 仍未覆盖」里的异质 TLV 项改写:
```markdown
### Phase 2c1(本版本新增)

- **异质 TLV** —— 标准 TLV(type+length 各1字节 + value)按 type 分派到不同 value 实体,sentinel 终止,未知 type 跳过。`dispatch={"1=SubnetMask","3=Router"}` 声明分派表。

示例:

```java
@ProtocolField(type=FieldType.LIST_TLV, tlvEndMarker=0xFF,
    dispatch={"1=SubnetMask", "3=Router", "53=DhcpMsgType"})
private List<Object> options;   // type=1→SubnetMask, type=3→Router, type=0xFF→End
```

### 仍未覆盖(后续 Phase)

- 非标准 TLV 元素结构(如 TCP Options 的 NOP 无 length、固定长度)
- 元素内字段级 sentinel(如 DNS 的「label 长度=0 表示结束」)
- 未知 TLV type 零丢失(RawOption 占位)
- 复杂条件(位掩码 / `&&`)
- 校验和 / CRC 钩子(IPv4/TCP/UDP 校验和、伪首部)
- 流重组 / 分片重组(过程性,留钩子)
```

- [ ] **Step 4: 提交**

```bash
git add README.md
git commit -m "docs: document Phase 2c1 heterogeneous TLV"
```

---

## 完成标志

全部 Task 完成后:
- [ ] `./mvnw test` 全绿(53 个测试)
- [ ] `./mvnw package` 成功
- [ ] 已知 type round-trip:DHCP 3 option → 标准字节 → 还原(类型正确)
- [ ] 未知 type 跳过:type=99 跳过,前后元素不受影响
- [ ] sentinel 终止:0xFF 停;空列表仅 0xFF
- [ ] dispatch 校验:类不存在/格式错 → 注册期报错
- [ ] Phase 1~2e 全量回归不破
