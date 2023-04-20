package com.github.monkeywie.proxyee.server;

import io.netty.util.AttributeKey;
import reactor.netty.Connection;

public interface ProxyChannelAttrs {
    static final AttributeKey<Connection> PROXY = AttributeKey.valueOf("$CONNECTION");
}
