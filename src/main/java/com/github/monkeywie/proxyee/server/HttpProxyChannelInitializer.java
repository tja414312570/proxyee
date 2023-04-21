package com.github.monkeywie.proxyee.server;

import com.github.monkeywie.proxyee.handler.HttpProxyInitializer;
import io.netty.channel.Channel;

public interface HttpProxyChannelInitializer {
    void accept(Channel channel, HttpProxyInitializer proxyInitializer);
}
