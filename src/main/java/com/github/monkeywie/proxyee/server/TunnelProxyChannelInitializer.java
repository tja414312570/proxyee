package com.github.monkeywie.proxyee.server;

import com.github.monkeywie.proxyee.handler.TunnelProxyInitializer;
import io.netty.channel.Channel;

public interface TunnelProxyChannelInitializer {
    void accept(Channel channel, TunnelProxyInitializer proxyInitializer);
}
