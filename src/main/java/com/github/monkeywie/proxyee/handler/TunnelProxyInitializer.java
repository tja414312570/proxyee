package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;

/**
 * http代理隧道，转发原始报文
 */
public class TunnelProxyInitializer extends ChannelInitializer {

    private final ProxyApplicationContext context;
    private Channel clientChannel;

    public TunnelProxyInitializer(Channel clientChannel
            , ProxyApplicationContext context) {
        this.clientChannel = clientChannel;
        this.context = context;
    }

    @Override
    protected void initChannel(Channel ch) throws Exception {
        if (context.getProxyHandler() != null) {
            ch.pipeline().addLast(context.getProxyHandler().get());
        }
        ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
            @Override
            public void channelRead(ChannelHandlerContext ctx0, Object msg0) throws Exception {
                clientChannel.writeAndFlush(msg0);
            }

            @Override
            public void channelUnregistered(ChannelHandlerContext ctx0) throws Exception {
                ctx0.channel().close();
                clientChannel.close();
            }

            @Override
            public void exceptionCaught(ChannelHandlerContext ctx0, Throwable cause) throws Exception {
                ctx0.channel().close();
                clientChannel.close();
                HttpProxyExceptionHandle exceptionHandle =context.getHttpProxyExceptionHandle();
                exceptionHandle.afterCatch(clientChannel, ctx0.channel(), cause);
            }
        });
    }
}
