# 如何测试你的协议

引擎自带 300+ 测试,其中可直接参考的模板:`netproto-core/src/test/java/com/netproto/` 下
`protocols/real/`(18 个真实协议族,权威字节向量)与 `core/Boundary*Test`(格式边界电池)。

## 1. 直连引擎(不起 Spring)

```java
ProtocolCodec<MyFrame> codec = new ProtocolCodec<>(MyFrame.class);

byte[] wire = codec.serialize(frame);        // 组装
MyFrame back = codec.deserialize(wire);      // 解析
```

夹具惯例:测试类内静态 `@Data @Protocol` 实体 + AssertJ 字节断言(`containsExactly` 逐字节,不许只比长度)。

## 2. 权威向量法(核心方法论)

> 测试的公信力来自**外部向量**,不是自己编码再自己解码。

四步:

```java
// ① 权威字节:规范示例 / 抓包 / 手工按 spec 推导(注释注明出处)
byte[] vector = {0x11, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x76, 0x87};

// ② 解码:逐字段断言
assertThat(codec.deserialize(vector).getStartAddr()).isEqualTo(0x006B);

// ③ 编码:从实体组装,字节级等于向量
assertThat(codec.serialize(built)).containsExactly(vector);

// ④ round-trip:对象级相等(Lombok equals)
```

**校验和类协议加一步自证**:在测试内放一个独立参考实现(CRC/累加和按 spec 手写),用公开标准向量证明参考实现正确(如 CRC-16/MODBUS 的 `"123456789" → 0x4B37`),再用它交叉验证引擎产物 —— 引擎、参考实现、标准向量三方一致才算数。

好向量的来源优先级:规范原文示例(RFC §示例、AUTOSAR PRS)> 公开标准校验向量(CRC cat catalog)> 抓包 > 手工推导。手工推导的向量,推导依据要写进注释。

## 3. 必测的边界习惯(来自 Boundary*Test 的教训清单)

| 类别 | 用例 |
|---|---|
| 截断 | 对完整帧做 **0..n-1 全前缀截断扫描**,每个截断点必须抛异常(不允许部分解析成功) |
| 超卖 | lengthField/countField 宣称大于实际 → 干净失败(`past end` 报错含需求量/剩余量) |
| 空/零 | count=0、空 payload、零长字符串、空 LIST(注意 count 自动回填) |
| 负值 | 计数 -1 = null 数组语义是有意设计;<-1 是垃圾应报错 |
| 条件两态 | presentIf 的每个分支都测,「条件不满足」也要断言字节缺席 |
| 端序 | 同帧混合 LE/BE 各测一遍;校验和字段 LE 时解码与回写都应正确 |
| 极值 | 无符号 63bit 上限、有符号负数、BCD 满 16 位 |

## 4. 常见坑(引擎行为,不是 bug)

- `lengthField/countField/presentIf` 只能引用**更早**的字段(前向引用注册期拒绝)—— 想引用后面的值,改实体字段顺序或用钩子;
- 位索引 `bitmap[n]` 按**声明 size** 从 MSB 数(8bit 字段的 bit2 = `bitmap[6]`);动态长度字段回退 Java 类型宽度;
- `LITTLE` 只支持整字节定长整数(位字段无字节序);FLOAT 支持 LITTLE;
- BYTES/STRING 与 NESTED 支持非字节对齐起始(位级读写),但 `lengthUnit=BITS` 的值必须是 8 的倍数;
- LIST 元素的最后一个字段必须自定界(size/lengthField/LIST),否则注册期拒绝(无法切分元素);
- 解码后 absent 字段保持 Java 默认值 —— 判断「字段是否在帧上」用 ranges(`lastFieldRanges`),不要用值是否为 0。

## 5. 跑法

```bash
mvn -pl netproto-core test                       # 全量
mvn -pl netproto-core test -Dtest='ModbusRtuRealTest'   # 单类
```

Windows Git Bash 过滤输出:`mvn test 2>&1 | tr -d '\r' | grep "Tests run" | tail -1`。
