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
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
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
import org.apache.commons.lang3.StringUtils;

import java.net.InetSocketAddress;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

/**
 * 代理协议解析
 */
@Slf4j
public class HttpProtocolDecodeHandler extends ChannelInboundHandlerAdapter {

    private final ProxyApplicationContext context;
    private ChannelFuture cf;
    private List requestList;

    public HttpProtocolDecodeHandler(ProxyApplicationContext context) {
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

    protected void resetAfter(final ChannelHandlerContext ctx,String name){
        String lastName = ctx.pipeline().lastContext().name();
        List<String> names = ctx.pipeline().names();
        boolean rest = false;
        for (int i = 0; i < names.size(); i++) {
            if(StringUtils.equals(name,name)){
                rest = true;
                continue;
            }
            if(rest){
                ctx.pipeline().remove(name);
            }
            if(StringUtils.equals(name,lastName)){
               break;
            }
        }

    }
    @Override
    public void channelRead(final ChannelHandlerContext ctx, final Object msg) throws Exception {
        System.err.println("\n-===========================" + (msg instanceof FullHttpRequest));
        FlowContext flowContext = FlowContext.get(ctx,this.context);
        System.err.println(flowContext);
        System.err.println(msg);
        //其它请求
        if (msg instanceof HttpRequest request) {
            DecoderResult result = request.decoderResult();
            Throwable cause = result.cause();
            if (cause instanceof DecoderException) {
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
            if (!flowContext.isConnected()) {
                flowContext.setRequestProto(ProtoUtil.getRequestProto(request));
                if (flowContext.getRequestProto() == null) { // bad request
                    logWrite(ctx.channel(), HttpResponseStatus.BAD_REQUEST);
                    ctx.channel().close();
                    return;
                }
                //请求是否放行
                HttpProxyAcceptHandler httpProxyAcceptHandler = this.context.getHttpProxyAcceptHandler();
                if (httpProxyAcceptHandler != null
                        && !httpProxyAcceptHandler.onAccept(request, ctx.channel())) {
                    logWrite(ctx.channel(), HttpResponseStatus.NOT_ACCEPTABLE);
                    ctx.channel().close();
                    return;
                }
                //非握请求
                if (!HttpMethod.CONNECT.equals(request.method())) {// 建立代理握手
                    logWrite(ctx.channel(), HttpResponseStatus.METHOD_NOT_ALLOWED);
                    ctx.channel().close();
                    return;
                }
                if (!authenticate(ctx, request,flowContext)) {
                    logWrite(ctx.channel(), HttpResponseStatus.FORBIDDEN);
                    ctx.channel().close();
                    return;
                }
                HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpsResponse.SUCCESS);
                ctx.writeAndFlush(response);
                ctx.channel().pipeline().remove("httpCodec");
                ReferenceCountUtil.release(msg);
                flowContext.setConnected(true);
            }else{
                flowContext.setReadied(true);
                flowContext.setInterceptPipeline(buildPipeline(flowContext));
                flowContext.getInterceptPipeline().setRequestProto(flowContext.getRequestProto().copy());
                // fix issue #27
                if (request.uri().indexOf("/") != 0) {
                    URL url = new URL(request.uri());
                    request.setUri(url.getFile());
                }
                flowContext.getInterceptPipeline().beforeRequest(ctx.channel(), request);
                ReferenceCountUtil.release(msg);
            }
        } else if (msg instanceof HttpContent) {
            if (flowContext.isConnected()) {
                if(flowContext.isReadied()){
                    flowContext.getInterceptPipeline().beforeRequest(ctx.channel(), (HttpContent) msg);
                }else{
                    ReferenceCountUtil.release(msg);
                }
            } else {
                logWrite(ctx.channel(), HttpResponseStatus.UNAUTHORIZED);
                ctx.channel().close();
                ReferenceCountUtil.release(msg);
            }
        } else {
            handleProxyData(ctx.channel(), msg, flowContext);
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

    private boolean authenticate(ChannelHandlerContext ctx, HttpRequest request,FlowContext flowContext) {
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
            flowContext.setAttribute(HttpAuthContext.AUTH_KEY,httpToken);
        }
        return true;
    }

    private void handleProxyData(Channel channel, Object msg, FlowContext flowContext) throws Exception {
        if (flowContext.getInterceptPipeline() == null) {
            flowContext. setInterceptPipeline(buildOnlyConnectPipeline());
            flowContext. getInterceptPipeline().setRequestProto(flowContext.getRequestProto().copy());
        }
        RequestProto pipeRp = flowContext.getInterceptPipeline().getRequestProto();
        boolean isChangeRp = false;
        if (flowContext.isHttp() && msg instanceof HttpRequest) {
            // check if request modified
            if (!pipeRp.equals(flowContext.getRequestProto())) {
                isChangeRp = true;
            }
        }

        if (isChangeRp || getChannelFuture() == null) {
            // connection异常 还有HttpContent进来，不转发
            if (flowContext.isHttp() && !(msg instanceof HttpRequest)) {
                System.err.println("忽略:" + msg);
                return;
            }
            flowContext.getInterceptPipeline().beforeConnect(channel);

            /*
             * 添加SSL client hello的Server Name Indication extension(SNI扩展) 有些服务器对于client
             * hello不带SNI扩展时会直接返回Received fatal alert: handshake_failure(握手错误)
             * 例如：https://cdn.mdn.mozilla.net/static/img/favicon32.7f3da72dcea1.png
             */
            System.err.println("转发;" + flowContext.isHttp() + msg);
            ChannelInitializer channelInitializer = flowContext.isHttp() ? new HttpProxyInitializer(flowContext)
                    : new TunnelProxyInitializer(flowContext);
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
            System.err.println(pipeRp.getHost() + "===>" + pipeRp.getPort());
            getChannelFuture().addListener((ChannelFutureListener) future -> {
                Throwable cause = future.cause();
                if (cause != null) {
                    log.warn("一个错误出现在写入数据{}", cause.getMessage(), cause);
                }
                if (future.isSuccess()) {
                    System.err.println("写入数据" + msg);
                    logWrite(future.channel(), msg);
                    synchronized (getRequestList()) {
                        getRequestList().forEach(obj -> future.channel().writeAndFlush(obj));
                        getRequestList().clear();
                        flowContext.setRemoteConnected(true);
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
                if (flowContext.isRemoteConnected()) {
                    logWrite(getChannelFuture().channel(), msg);
                } else {
                    getRequestList().add(msg);
                }
            }
        }
    }

    private HttpProxyInterceptPipeline buildPipeline(FlowContext flowContext) {
        HttpProxyInterceptPipeline interceptPipeline = new HttpProxyInterceptPipeline(new HttpProxyIntercept() {
            @Override
            public void beforeRequest(Channel clientChannel, HttpRequest httpRequest, HttpProxyInterceptPipeline pipeline)
                    throws Exception {
                handleProxyData(clientChannel, httpRequest, flowContext);
            }

            @Override
            public void beforeRequest(Channel clientChannel, HttpContent httpContent, HttpProxyInterceptPipeline pipeline)
                    throws Exception {
                handleProxyData(clientChannel, httpContent, flowContext);
            }

            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse,
                                      HttpProxyInterceptPipeline pipeline) throws Exception {
                logWrite(clientChannel, httpResponse);
                if (HttpHeaderValues.WEBSOCKET.toString().equals(httpResponse.headers().get(HttpHeaderNames.UPGRADE))) {
                    // websocket转发原始报文
                    proxyChannel.pipeline().remove("httpCodec");
                    clientChannel.pipeline().remove("httpCodec");
                }

            }


            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent,
                                      HttpProxyInterceptPipeline pipeline) throws Exception {
                logWrite(clientChannel, httpContent);
            }
        });
        this.context.getProxyInterceptInitializer().init(interceptPipeline);
        return interceptPipeline;
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
}
