package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.domain.FlowContext;
import com.github.monkeywie.proxyee.util.ProtoUtil.RequestProto;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.concurrent.Flow;

/**
 * HTTP代理，转发解码后的HTTP报文
 */
@Getter
@AllArgsConstructor
public class HttpProxyInitializer extends ChannelInitializer {

    private final FlowContext flowContext;

    @Override
    protected void initChannel(Channel ch) throws Exception {
        this.flowContext.bindProxyChannel(ch);
        this.flowContext.getApplicationContext().getHttpProxyChannelInitializer()
                .accept(ch,this);
    }
}
