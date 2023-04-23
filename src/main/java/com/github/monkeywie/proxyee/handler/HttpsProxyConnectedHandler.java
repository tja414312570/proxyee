package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.crt.CertPool;
import io.netty.buffer.ByteBuf;
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
        ByteBuf byteBuf = (ByteBuf) msg;
        int port = ((InetSocketAddress) ctx.channel().localAddress()).getPort();
        ctx.pipeline().addFirst("httpCodec",this.context.getHttpCodecBuilder().get());
        SslContext sslCtx = SslContextBuilder
                .forServer(this.context.getCertificateInfo().getServerPriKey(),
                        CertPool.getCert(port, ((InetSocketAddress) ctx.channel().localAddress()).getHostName(), this.context.getCertificateInfo())).build();
        ctx.pipeline().addFirst("sslHandle", sslCtx.newHandler(ctx.alloc()));
        // 重新过一遍pipeline，拿到解密后的的http报文
        ctx.pipeline().fireChannelRead(msg);
    }
}
