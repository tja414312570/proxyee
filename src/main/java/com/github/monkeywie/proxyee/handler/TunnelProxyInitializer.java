package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.domain.FlowContext;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.util.ProtoUtil;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * http代理隧道，转发原始报文
 */
@Getter
@AllArgsConstructor
public class TunnelProxyInitializer extends ChannelInitializer {
    private final FlowContext flowContext;
    @Override
    protected void initChannel(Channel ch) throws Exception {
        this.flowContext.bindProxyChannel(ch);
        this.flowContext.getApplicationContext().getTunnelProxyChannelInitializer()
                .accept(ch,this);
    }
}
