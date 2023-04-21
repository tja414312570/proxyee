package com.github.monkeywie.proxyee.server;

import com.github.monkeywie.proxyee.handler.HttpProxyInitializer;
import io.netty.util.AttributeKey;

public interface ProxyChannelAttrs {
    static final AttributeKey<HttpProxyInitializer> HTTP_PROXY = AttributeKey.valueOf("$HttpProxyInitializer");
}
