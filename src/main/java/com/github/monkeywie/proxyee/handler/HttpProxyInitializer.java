package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.util.ProtoUtil.RequestProto;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * HTTP代理，转发解码后的HTTP报文
 */
@Getter
@AllArgsConstructor
public class HttpProxyInitializer extends ChannelInitializer {

    private final Channel clientChannel;
    private final RequestProto requestProto;
    private final ProxyApplicationContext context;
    @Override
    protected void initChannel(Channel ch) throws Exception {
        this.context.getHttpProxyChannelInitializer()
                .accept(ch,this);
    }
}
