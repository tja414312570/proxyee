package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.util.ReferenceCountUtil;

/**
 * 隧道消息转发
 */
public class ChannelTunnelMsgForwardAdapter extends ChannelInboundHandlerAdapter {
    protected Channel clientChannel;
    protected ProxyApplicationContext context;
    public ChannelTunnelMsgForwardAdapter(Channel channel, ProxyApplicationContext context){
        this.clientChannel = channel;
        this.context = context;
    }
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!clientChannel.isOpen()) {
            ReferenceCountUtil.release(msg);
            return;
        }
        System.err.println((msg instanceof FullHttpRequest)+"--tun->"+msg);
        clientChannel.writeAndFlush(msg);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        super.channelInactive(ctx);
        System.err.println("通道关闭"+ctx.channel());
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        ctx.channel().close();
//        clientChannel.close();
        System.err.println("通道取消注册");
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        ctx.channel().close();
        clientChannel.close();
        HttpProxyExceptionHandle exceptionHandle =context.getHttpProxyExceptionHandle();
        exceptionHandle.afterCatch(clientChannel, ctx.channel(), cause);
    }
}
