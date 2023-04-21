package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.DecoderResult;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.util.ReferenceCountUtil;

public class HttpProxyClientHandler extends ChannelInboundHandlerAdapter {

    private final ProxyApplicationContext context;
    private Channel clientChannel;

    public HttpProxyClientHandler(Channel clientChannel, ProxyApplicationContext context) {
        this.clientChannel = clientChannel;
        this.context = context;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        //客户端channel已关闭则不转发了
        if (!clientChannel.isOpen()) {
            ReferenceCountUtil.release(msg);
            return;
        }
        HttpProxyInterceptPipeline interceptPipeline = ((HttpProxyServerHandler) clientChannel.pipeline()
                .get("serverHandle")).getInterceptPipeline();
        if (msg instanceof HttpResponse) {
            DecoderResult decoderResult = ((HttpResponse) msg).decoderResult();
            Throwable cause = decoderResult.cause();
            if(cause != null){
                ReferenceCountUtil.release(msg);
                this.exceptionCaught(ctx, cause);
                return;
            }
            interceptPipeline.afterResponse(clientChannel, ctx.channel(), (HttpResponse) msg);
        } else if (msg instanceof HttpContent) {
            interceptPipeline.afterResponse(clientChannel, ctx.channel(), (HttpContent) msg);
        } else {
            clientChannel.writeAndFlush(msg);
        }
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        ctx.channel().close();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        ctx.channel().close();
        clientChannel.close();
        HttpProxyExceptionHandle exceptionHandle = this.context.getHttpProxyExceptionHandle();
        exceptionHandle.afterCatch(clientChannel, ctx.channel(), cause);
    }
}
