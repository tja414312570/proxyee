package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderResult;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.util.ReferenceCountUtil;

/**
 * Http消息转发
 */
public class ChannelHttpMsgForwardAdapter extends ChannelTunnelMsgForwardAdapter {

    public  ChannelHttpMsgForwardAdapter(Channel clientChannel, ProxyApplicationContext context) {
        super(clientChannel,context);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        //客户端channel已关闭则不转发了
        System.err.println("响应转发:"+msg);
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
            System.err.println((msg instanceof FullHttpRequest)+"----------------------http->");
//            ChannelFuture channelFuture = clientChannel.writeAndFlush(msg);
            interceptPipeline.afterResponse(clientChannel, ctx.channel(), (HttpResponse) msg);
        } else if (msg instanceof HttpContent) {
            System.err.println((msg instanceof FullHttpRequest)+"----------------------httpc->");
//            clientChannel.writeAndFlush(msg);
            interceptPipeline.afterResponse(clientChannel, ctx.channel(), (HttpContent) msg);
//            clientChannel.close();
        } else {
            clientChannel.writeAndFlush(msg);
        }
    }
}
