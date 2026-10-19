package com.example.netproto.core;

/**
 * 组装期钩子:StackEncoder 注入内层 payload 字节后、编码本层之前回调,
 * 用于调整依赖 payload 尺寸的长度类字段(ipv4.totalLength / udp.length)。
 */
public interface PayloadAware {

    void onPayload(byte[] innerPayload);
}
