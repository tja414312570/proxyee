package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.util.ProtoUtil.RequestProto;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import lombok.Getter;

/**
 * HTTP代理，转发解码后的HTTP报文
 */
@Getter
public class HttpProxyInitializer extends ChannelInitializer {

    private Channel clientChannel;
    private RequestProto requestProto;
    private ProxyApplicationContext context;

    public HttpProxyInitializer(Channel clientChannel, RequestProto requestProto,
                                ProxyApplicationContext context) {
        this.clientChannel = clientChannel;
        this.requestProto = requestProto;
        this.context = context;
    }

    @Override
    protected void initChannel(Channel ch) throws Exception {
        this.context.getProxyChannelInitializer()
                .accept(ch,this);

    }
}
