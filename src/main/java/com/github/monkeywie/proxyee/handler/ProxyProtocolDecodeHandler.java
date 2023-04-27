package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.consts.HttpsResponse;
import com.github.monkeywie.proxyee.crt.CertPool;
import com.github.monkeywie.proxyee.domain.FlowContext;
import com.github.monkeywie.proxyee.intercept.HttpProxyIntercept;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.server.accept.HttpProxyAcceptHandler;
import com.github.monkeywie.proxyee.server.auth.HttpAuthContext;
import com.github.monkeywie.proxyee.server.auth.HttpProxyAuthenticationProvider;
import com.github.monkeywie.proxyee.server.auth.model.HttpToken;
import com.github.monkeywie.proxyee.util.ProtoUtil;
import com.github.monkeywie.proxyee.util.ProtoUtil.RequestProto;
import com.google.gson.Gson;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.DecoderResult;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.resolver.NoopAddressResolverGroup;
import io.netty.util.ReferenceCountUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.TlsClientProtocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 代理协议解析
 */
@Slf4j
public class ProxyProtocolDecodeHandler extends ChannelInboundHandlerAdapter implements ChannelOutboundHandler {

    private final ProxyApplicationContext context;
    private ChannelFuture cf;
    private List requestList;
    private boolean onlyForward;

    public ProxyProtocolDecodeHandler(ProxyApplicationContext context) {
        this.context = context;
    }

    protected ChannelFuture getChannelFuture() {
        return cf;
    }

    protected void setChannelFuture(ChannelFuture cf) {
        this.cf = cf;
    }

    protected List getRequestList() {
        return requestList;
    }

    protected void setRequestList(List requestList) {
        this.requestList = requestList;
    }

    protected void resetAfter(final ChannelHandlerContext ctx,String beanName){
        String lastName = ctx.pipeline().lastContext().name();
        if(StringUtils.equals(beanName,lastName)){
            return;
        }
//        Iterator<Map.Entry<String, ChannelHandler>> iterator = ctx.pipeline().iterator();
//        boolean removable = false;
//        while(iterator.hasNext()){
//            String name = iterator.next().getKey();
//            if (StringUtils.equals(name, beanName)) {
//                removable = true;
//                continue;
//            }
//            if (removable) {
//                iterator.remove();
//            }
//            if (StringUtils.equals(name, lastName)) {
//                break;
//            }
//        }
        List<String> names = ctx.pipeline().names();
        boolean removable = false;
        for (String name : names) {
            if (StringUtils.equals(name, beanName)) {
                removable = true;
                continue;
            }
            if (removable) {
                ctx.pipeline().remove(name);
            }
            if (StringUtils.equals(name, lastName)) {
                break;
            }
        }
    }

    @Override
    public void channelRead(final ChannelHandlerContext ctx, final Object msg) throws Exception {
//        System.err.println("\n-===========================" +ctx.channel().id()+"==="+ (msg.getClass()));
//        System.err.println(msg);
//        byte[] bytes = ByteBufUtil.getBytes((ByteBuf) msg);
//        System.err.println(Arrays.toString(bytes));
//        System.err.println("--------------------------------"+ctx.channel().id());
        FlowContext flowContext = FlowContext.get(ctx,this.context);
        if(onlyForward){
            ctx.fireChannelRead(msg);
            return;
        }
        byte aByte = ((ByteBuf) msg).getByte(0);
        switch (aByte) {
            case 22:
                String hostName;
                int port;
                if(flowContext.isNews()){//https代理 ssl证书
                    System.err.println("代理服务器ssl");
                    port = ((InetSocketAddress) ctx.channel().localAddress()).getPort();
                    hostName = ((InetSocketAddress) ctx.channel().localAddress()).getHostName();
                    SslContext sslCtx =  SslContextBuilder
                            .forServer(this.context.getCertificateInfo().getServerPriKey(),
                                    CertPool.getCert(port,hostName, this.context.getCertificateInfo()))
                            .build();
                    ctx.pipeline().addFirst("proxySslHandle", sslCtx.newHandler(ctx.alloc()));
                    ctx.pipeline().fireChannelRead(msg);
                }else{//目标网站ssl代理

                    flowContext.setProxySSl(true);
                    resetAfter(ctx,"serverHandle");
                    port = ((InetSocketAddress) ctx.channel().localAddress()).getPort();
                    hostName =  flowContext.getRequestProto().getHost();
                    System.err.println("目标服服务器ssl"+"==>"+port+"===>"+hostName);
                    flowContext.getRequestProto().setSsl(true);
                    SslContext sslCtx =  SslContextBuilder
                            .forServer(this.context.getCertificateInfo().getServerPriKey(),
                                    CertPool.getCert(port,hostName, this.context.getCertificateInfo()))
                            .build();
                    ctx.pipeline().addLast("serverSSlHandler", sslCtx.newHandler(ctx.alloc()));
                    //固定当前handler
                    ctx.pipeline().addLast("nextProtocolDecoder",new ProxyProtocolDecodeHandler(this.context));
                    this.onlyForward = true;
                    ctx.fireChannelRead(msg);
                }
                return;
            case 5:
                System.err.println("socket5代理");//接收 05 00 不接受 05 0xff https://blog.csdn.net/kevingzy/article/details/127808550
                ByteBuf buf = Unpooled.buffer(2);
                buf.writeByte(0x05);
                buf.writeByte(0xff);
                ctx.writeAndFlush(buf);
//                resetAfter(ctx,"serverHandle");
                return;
            default:

                if (isHttp((ByteBuf) msg)) {
                    flowContext.setHttp(true);
                    System.err.println("http协议");
                    try{
                        ctx.pipeline().addLast("httpCodec",this.context.getHttpCodecBuilder().get());
                        ctx.pipeline().addLast("httpDispatcher",new HttpProtocolDecodeHandler(this.context));
                    }catch (Exception e){
                        System.err.println(ctx.channel().id());
                        e.printStackTrace();
                    }
                    ctx.fireChannelRead(msg);
                    return;
                }
                System.err.println("其他协议"+aByte);
                ctx.fireChannelRead(msg);

        }

    }

    private boolean isHttp(ByteBuf byteBuf) {
        byte[] bytes = new byte[8];
        byteBuf.getBytes(0, bytes);
        String methodToken = new String(bytes);
        return methodToken.startsWith("GET ") || methodToken.startsWith("POST ") || methodToken.startsWith("HEAD ")
                || methodToken.startsWith("PUT ") || methodToken.startsWith("DELETE ") || methodToken.startsWith("OPTIONS ")
                || methodToken.startsWith("CONNECT ") || methodToken.startsWith("TRACE ");
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        if (getChannelFuture() != null) {
            getChannelFuture().channel().close();
        }
        ctx.channel().close();
        if (this.context.getHttpProxyAcceptHandler() != null) {
            this.context.getHttpProxyAcceptHandler().onClose(ctx.channel());
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        System.err.println("出现错误:--->");
        cause.printStackTrace();
        if (getChannelFuture() != null) {
            getChannelFuture().channel().close();
        }
        ctx.channel().close();
        this.context.getHttpProxyExceptionHandle().beforeCatch(ctx.channel(), cause);
    }

    private void logWrite(Channel channel, Object msg) {
        ChannelFuture channelFuture = channel.writeAndFlush(msg);
        channelFuture.addListener(future -> {
            Throwable cause = future.cause();
            if (cause != null) {
                log.warn("一个错误出现在写入数据{}", cause.getMessage(), cause);
                log.warn("错误的数据{}", msg);
            }
        });
    }

    private void logWrite(Channel channel, HttpResponseStatus status) {
        logWrite(channel, new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status));
    }

    // fix issue #186: 不拦截https报文时，暴露一个扩展点用于代理设置，并且保持一致的编程接口
    private HttpProxyInterceptPipeline buildOnlyConnectPipeline() {
        HttpProxyInterceptPipeline interceptPipeline = new HttpProxyInterceptPipeline(new HttpProxyIntercept());
        this.context.getProxyInterceptInitializer().init(interceptPipeline);
        return interceptPipeline;
    }

    @Override
    public void bind(ChannelHandlerContext ctx, SocketAddress localAddress,
                     ChannelPromise promise) throws Exception {
        ctx.bind(localAddress, promise);
    }

    @Override
    public void connect(ChannelHandlerContext ctx, SocketAddress remoteAddress,
                        SocketAddress localAddress, ChannelPromise promise) throws Exception {
        ctx.connect(remoteAddress, localAddress, promise);
    }

    @Override
    public void disconnect(ChannelHandlerContext ctx, ChannelPromise promise)
            throws Exception {
        ctx.disconnect(promise);
    }

    @Override
    public void close(ChannelHandlerContext ctx, ChannelPromise promise)
            throws Exception {
        ctx.close(promise);
    }

    @Override
    public void deregister(ChannelHandlerContext ctx, ChannelPromise promise) throws Exception {
        ctx.deregister(promise);
    }

    @Override
    public void read(ChannelHandlerContext ctx) throws Exception {
        ctx.read();
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
//        FlowContext flowContext = FlowContext.get(ctx);
//        if(msg[0] == 20 && flowContext.isProxySSl() && !flowContext.isProxySslCompleted()){
//            System.err.println("设置ssl建立完成");
//            flowContext.setProxySslCompleted(true);
//        }

        ctx.write(msg, promise);
    }
    @Override
    public void flush(ChannelHandlerContext ctx) throws Exception {
        ctx.flush();
    }
}
