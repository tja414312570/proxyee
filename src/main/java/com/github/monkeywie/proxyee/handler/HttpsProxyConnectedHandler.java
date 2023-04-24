package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.crt.CertPool;
import com.github.monkeywie.proxyee.domain.FlowContext;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import lombok.AllArgsConstructor;

import java.net.InetSocketAddress;

@AllArgsConstructor
public class HttpsProxyConnectedHandler extends ChannelInboundHandlerAdapter {
    private ProxyApplicationContext context;
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        int port = ((InetSocketAddress) ctx.channel().localAddress()).getPort();
        FlowContext flowContext = FlowContext.get(ctx, this.context);
        SslContext sslCtx = SslContextBuilder
                    .forServer(this.context.getCertificateInfo().getServerPriKey(),
                            CertPool.getCert(port, ((InetSocketAddress) ctx.channel().localAddress()).getHostName(), this.context.getCertificateInfo())).build();
        ctx.pipeline().addLast("sslHandle", sslCtx.newHandler(ctx.alloc()));
        ctx.pipeline().addLast("httpCodec",this.context.getHttpCodecBuilder().get());
        ctx.fireChannelRead(msg);
    }
}
