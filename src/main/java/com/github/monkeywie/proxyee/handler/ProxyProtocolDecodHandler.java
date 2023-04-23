package com.github.monkeywie.proxyee.handler;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.consts.HttpsResponse;
import com.github.monkeywie.proxyee.crt.CertPool;
import com.github.monkeywie.proxyee.intercept.HttpProxyIntercept;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.server.accept.HttpProxyAcceptHandler;
import com.github.monkeywie.proxyee.server.auth.HttpAuthContext;
import com.github.monkeywie.proxyee.server.auth.HttpProxyAuthenticationProvider;
import com.github.monkeywie.proxyee.server.auth.model.HttpToken;
import com.github.monkeywie.proxyee.util.ProtoUtil;
import com.github.monkeywie.proxyee.util.ProtoUtil.RequestProto;
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
import io.netty.resolver.NoopAddressResolverGroup;
import io.netty.util.ReferenceCountUtil;
import lombok.extern.slf4j.Slf4j;

import java.net.InetSocketAddress;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

/**
 * 代理协议解析
 */
@Slf4j
public class ProxyProtocolDecodHandler extends ChannelInboundHandlerAdapter {

    private final ProxyApplicationContext context;
    private ChannelFuture cf;
    private RequestProto requestProto;
    private int status = 0;
    private HttpProxyInterceptPipeline interceptPipeline;
    private List requestList;
    private boolean isConnect;

    private byte[] httpTagBuf;

    protected ChannelFuture getChannelFuture() {
        return cf;
    }

    protected void setChannelFuture(ChannelFuture cf) {
        this.cf = cf;
    }

    protected boolean getIsConnect() {
        return isConnect;
    }

    protected void setIsConnect(boolean isConnect) {
        this.isConnect = isConnect;
    }

    protected List getRequestList() {
        return requestList;
    }

    protected void setRequestList(List requestList) {
        this.requestList = requestList;
    }

    protected RequestProto getRequestProto() {
        return requestProto;
    }

    protected void setRequestProto(RequestProto requestProto) {
        this.requestProto = requestProto;
    }

    protected int getStatus() {
        return status;
    }

    protected void setStatus(int status) {
        this.status = status;
    }

    public HttpProxyInterceptPipeline getInterceptPipeline() {
        return interceptPipeline;
    }

    protected void setInterceptPipeline(HttpProxyInterceptPipeline interceptPipeline) {
        this.interceptPipeline = interceptPipeline;
    }

    public ProxyProtocolDecodHandler(ProxyApplicationContext context) {
        this.context = context;
    }


    @Override
    public void channelRead(final ChannelHandlerContext ctx, final Object msg) throws Exception {
        System.err.println("\n-==========================="+(msg instanceof FullHttpRequest));
        System.err.println(msg);
        if(msg instanceof  ByteBuf) {
            byte aByte = ((ByteBuf) msg).getByte(0);
            switch (aByte) {
                case 22:
                    System.err.println("tls握手");
                    ctx.channel().pipeline().addLast(new HttpsProxyConnectedHandler(this.context));
                    ctx.fireChannelRead(msg);
                    return;
                case 5:
                    System.err.println("socket5代理");//接收 05 00 不接受 05 0xff https://blog.csdn.net/kevingzy/article/details/127808550
                    ByteBuf buf = Unpooled.buffer(2);
                    buf.writeByte(0x05);
                    buf.writeByte(0xff);
                    ctx.writeAndFlush(buf);
                    return;
                default:
                    System.err.println("其他协议");
            }
        }
        //其它请求
        if (msg instanceof HttpRequest) {
            HttpRequest request = (HttpRequest) msg;
            DecoderResult result = request.decoderResult();
            Throwable cause = result.cause();
            if (cause instanceof DecoderException) {
                setStatus(2);
                HttpResponseStatus status = null;

                if (cause instanceof TooLongHttpLineException) {
                    status = HttpResponseStatus.REQUEST_URI_TOO_LONG;
                } else if (cause instanceof TooLongHttpHeaderException) {
                    status = HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE;
                } else if (cause instanceof TooLongHttpContentException) {
                    status = HttpResponseStatus.REQUEST_ENTITY_TOO_LARGE;
                }

                if (status == null) {
                    status = HttpResponseStatus.BAD_REQUEST;
                }

                HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status);
                ctx.writeAndFlush(response);
                //ctx.channel().pipeline().remove("httpCodec");
                ReferenceCountUtil.release(msg);
                return;
            }

            // The first time a connection is established, the host and port number are taken and the proxy handshake is processed.
            if (getStatus() == 0) {
                setRequestProto(ProtoUtil.getRequestProto(request));
                if (getRequestProto() == null) { // bad request
                    ctx.channel().close();
                    return;
                }
                // 首次连接处理
                HttpProxyAcceptHandler httpProxyAcceptHandler = this.context.getHttpProxyAcceptHandler();
                if (httpProxyAcceptHandler != null
                        && !httpProxyAcceptHandler.onAccept(request, ctx.channel())) {
                    setStatus(2);
                    ctx.channel().close();
                    return;
                }
                // 代理身份验证
                if (!authenticate(ctx, request)) {
                    setStatus(2);
                    ctx.channel().close();
                    return;
                }
                setStatus(1);
                if (HttpMethod.CONNECT.equals(request.method())) {// 建立代理握手
                    setStatus(2);
                    HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpsResponse.SUCCESS);
                    ctx.writeAndFlush(response);
                    ctx.channel().pipeline().remove("httpCodec");
                    // fix issue #42
                    ReferenceCountUtil.release(msg);
                    return;
                }
            }
            setInterceptPipeline(buildPipeline());
            getInterceptPipeline().setRequestProto(getRequestProto().copy());
            // fix issue #27
            if (request.uri().indexOf("/") != 0) {
                URL url = new URL(request.uri());
                request.setUri(url.getFile());
            }
            getInterceptPipeline().beforeRequest(ctx.channel(), request);
            ReferenceCountUtil.release(msg);
        } else if (msg instanceof HttpContent) {
            if (getStatus() != 2) {
                getInterceptPipeline().beforeRequest(ctx.channel(), (HttpContent) msg);
            } else {
                ReferenceCountUtil.release(msg);
                setStatus(1);
            }
        } else { // ssl和websocket的握手处理
            ByteBuf byteBuf = (ByteBuf) msg;
//            System.err.println(new Gson().toJson(ByteBufUtil.getBytes(byteBuf)));
            if (this.context.isHandleSsl() && byteBuf.getByte(0) == 22) {// ssl握手
                getRequestProto().setSsl(true);
                int port = ((InetSocketAddress) ctx.channel().localAddress()).getPort();
                ctx.pipeline().addFirst("httpCodec",this.context.getHttpCodecBuilder().get());
                SslContext sslCtx = SslContextBuilder
                        .forServer(this.context.getCertificateInfo().getServerPriKey(),
                                CertPool.getCert(port, getRequestProto().getHost(), this.context.getCertificateInfo())).build();
                ctx.pipeline().addFirst("sslHandle", sslCtx.newHandler(ctx.alloc()));
                // 重新过一遍pipeline，拿到解密后的的http报文
                ctx.pipeline().fireChannelRead(msg);
                return;
            }

            if (byteBuf.readableBytes() < 8) {
                httpTagBuf = new byte[byteBuf.readableBytes()];
                byteBuf.readBytes(httpTagBuf);
                ReferenceCountUtil.release(msg);
                return;
            }
            if (httpTagBuf != null) {
                byte[] tmp = new byte[byteBuf.readableBytes()];
                byteBuf.readBytes(tmp);
                byteBuf.writeBytes(httpTagBuf);
                byteBuf.writeBytes(tmp);
                httpTagBuf = null;
            }

            // 如果connect后面跑的是HTTP报文，也可以抓包处理
            if (isHttp(byteBuf)) {
                ctx.pipeline().addFirst("httpCodec", new HttpServerCodec());
                ctx.pipeline().fireChannelRead(msg);
                return;
            }
            System.err.println("转发数据"+msg+"===>"+ctx.channel());
            handleProxyData(ctx.channel(), msg, false);
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
        if (getChannelFuture() != null) {
            getChannelFuture().channel().close();
        }
        ctx.channel().close();
        this.context.getHttpProxyExceptionHandle().beforeCatch(ctx.channel(), cause);
    }

    private boolean authenticate(ChannelHandlerContext ctx, HttpRequest request) {
        if (this.context.getAuthenticationProvider() != null) {
            HttpProxyAuthenticationProvider authProvider = this.context.getAuthenticationProvider();

            // Disable auth for request?
            if (!authProvider.matches(request)) {
                return true;
            }

            HttpToken httpToken = authProvider.authenticate(request);
            if (httpToken == null) {
                HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpsResponse.UNAUTHORIZED);
                response.headers().set(HttpHeaderNames.PROXY_AUTHENTICATE, authProvider.authType() + " realm=\"" + authProvider.authRealm() + "\"");
                ctx.writeAndFlush(response);
                return false;
            }
            HttpAuthContext.setToken(ctx.channel(), httpToken);
        }
        return true;
    }

    private void handleProxyData(Channel channel, Object msg, boolean isHttp) throws Exception {
        if (getInterceptPipeline() == null) {
            setInterceptPipeline(buildOnlyConnectPipeline());
            getInterceptPipeline().setRequestProto(getRequestProto().copy());
        }
        RequestProto pipeRp = getInterceptPipeline().getRequestProto();
        boolean isChangeRp = false;
        if (isHttp && msg instanceof HttpRequest) {
            // check if request modified
            if (!pipeRp.equals(getRequestProto())) {
                isChangeRp = true;
            }
        }

        if (isChangeRp || getChannelFuture() == null) {
            // connection异常 还有HttpContent进来，不转发
            if (isHttp && !(msg instanceof HttpRequest)) {
                System.err.println("忽略:"+msg);
                return;
            }
            getInterceptPipeline().beforeConnect(channel);

            /*
             * 添加SSL client hello的Server Name Indication extension(SNI扩展) 有些服务器对于client
             * hello不带SNI扩展时会直接返回Received fatal alert: handshake_failure(握手错误)
             * 例如：https://cdn.mdn.mozilla.net/static/img/favicon32.7f3da72dcea1.png
             */
            System.err.println("转发;"+isHttp+msg);
            ChannelInitializer channelInitializer = isHttp ? new HttpProxyInitializer(channel, pipeRp, this.context)
                    : new TunnelProxyInitializer(channel, this.context);
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(this.context.getProxyGroup()) // 注册线程池
                    .channel(NioSocketChannel.class)
                    .handler(channelInitializer);
            if (this.context.getProxyHandler() != null) {
                // 代理服务器解析DNS和连接
                bootstrap.resolver(NoopAddressResolverGroup.INSTANCE);
            } else {
                bootstrap.resolver(this.context.getResolver());
            }
            setRequestList(new LinkedList());
            setChannelFuture(bootstrap.connect(pipeRp.getHost(), pipeRp.getPort()));
            System.err.println(pipeRp.getHost()+"===>"+pipeRp.getPort());
            getChannelFuture().addListener((ChannelFutureListener) future -> {
                Throwable cause = future.cause();
                if(cause != null){
                    log.warn("一个错误出现在写入数据{}",cause.getMessage(),cause);
                }
                if (future.isSuccess()) {
                    System.err.println("写入数据"+msg);
                      logWrite(future.channel(),msg);
                    synchronized (getRequestList()) {
                        getRequestList().forEach(obj -> future.channel().writeAndFlush(obj));
                        getRequestList().clear();
                        setIsConnect(true);
                    }
                } else {
                    synchronized (getRequestList()) {
                        getRequestList().forEach(obj -> ReferenceCountUtil.release(obj));
                        getRequestList().clear();
                    }
                    this.context.getHttpProxyExceptionHandle().beforeCatch(channel, future.cause());
                    future.channel().close();
                    channel.close();
                }
            });
        } else {
            synchronized (getRequestList()) {
                if (getIsConnect()) {
                   logWrite(getChannelFuture().channel(),msg);
                } else {
                    getRequestList().add(msg);
                }
            }
        }
    }

    private HttpProxyInterceptPipeline buildPipeline() {
        HttpProxyInterceptPipeline interceptPipeline = new HttpProxyInterceptPipeline(new HttpProxyIntercept() {
            @Override
            public void beforeRequest(Channel clientChannel, HttpRequest httpRequest, HttpProxyInterceptPipeline pipeline)
                    throws Exception {
                handleProxyData(clientChannel, httpRequest, true);
            }

            @Override
            public void beforeRequest(Channel clientChannel, HttpContent httpContent, HttpProxyInterceptPipeline pipeline)
                    throws Exception {
                handleProxyData(clientChannel, httpContent, true);
            }

            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse,
                                      HttpProxyInterceptPipeline pipeline) throws Exception {
                logWrite(clientChannel,httpResponse);
                if (HttpHeaderValues.WEBSOCKET.toString().equals(httpResponse.headers().get(HttpHeaderNames.UPGRADE))) {
                    // websocket转发原始报文
                    proxyChannel.pipeline().remove("httpCodec");
                    clientChannel.pipeline().remove("httpCodec");
                }

            }



            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent,
                                      HttpProxyInterceptPipeline pipeline) throws Exception {
                logWrite(clientChannel,httpContent);
            }
        });
        this.context.getProxyInterceptInitializer().init(interceptPipeline);
        return interceptPipeline;
    }
    private void logWrite(Channel clientChannel, Object msg) {
        ChannelFuture channelFuture = clientChannel.writeAndFlush(msg);
        channelFuture.addListener(future->{
            Throwable cause = future.cause();
            if(cause != null){
                log.warn("一个错误出现在写入数据{}",cause.getMessage(),cause);
                log.warn("错误的数据{}",msg);
            }
        });
    }
    // fix issue #186: 不拦截https报文时，暴露一个扩展点用于代理设置，并且保持一致的编程接口
    private HttpProxyInterceptPipeline buildOnlyConnectPipeline() {
        HttpProxyInterceptPipeline interceptPipeline = new HttpProxyInterceptPipeline(new HttpProxyIntercept());
        this.context.getProxyInterceptInitializer().init(interceptPipeline);
        return interceptPipeline;
    }
}
