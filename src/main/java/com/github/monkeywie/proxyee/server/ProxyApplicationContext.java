package com.github.monkeywie.proxyee.server;

import com.github.monkeywie.proxyee.crt.CertPool;
import com.github.monkeywie.proxyee.crt.CertUtil;
import com.github.monkeywie.proxyee.domain.CertificateInfo;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.handler.HttpProxyServerHandler;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.proxy.ProxyConfig;
import com.github.monkeywie.proxyee.server.accept.HttpProxyAcceptHandler;
import com.github.monkeywie.proxyee.server.auth.HttpProxyAuthenticationProvider;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.proxy.HttpProxyHandler;
import io.netty.handler.proxy.ProxyHandler;
import io.netty.handler.proxy.Socks4ProxyHandler;
import io.netty.handler.proxy.Socks5ProxyHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.resolver.AddressResolverGroup;
import io.netty.resolver.DefaultAddressResolverGroup;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;

@Slf4j
@Data
public class ProxyApplicationContext{
    protected NioEventLoopGroup proxyGroup;
    protected NioEventLoopGroup bossGroup;
    protected SslContext clientSslContext;
    protected HttpProxyInterceptInitializer proxyInterceptInitializer;
    protected HttpProxyExceptionHandle httpProxyExceptionHandle;
    protected CertificateInfo certificateInfo;
    protected HttpProxyAuthenticationProvider authenticationProvider;
    protected ProxyHandler proxyHandler;
    protected NioEventLoopGroup workerGroup;
    protected HttpProxyAcceptHandler httpProxyAcceptHandler;
    protected Map<String,ChannelHandler> channelHandlers = new LinkedHashMap<>();
    private String host;
    private int port;
    private AddressResolverGroup<? extends SocketAddress> resolver;
    private boolean handleSsl;

    public void init(HttpProxyServerConfig serverConfig) {
        try {
            ProxyConfig proxyConfig = serverConfig.getProxyConfig();
            resolver = DefaultAddressResolverGroup.INSTANCE;
            if (proxyConfig != null) {
                InetSocketAddress inetSocketAddress = new InetSocketAddress(proxyConfig.getHost(),
                        proxyConfig.getPort());
                String username = proxyConfig.getUsername();
                String password = proxyConfig.getPassword();
                boolean isAuth = username!= null && password != null;
                proxyHandler =  switch (proxyConfig.getProxyType()) {
                    case SOCKS4-> new Socks4ProxyHandler(inetSocketAddress);
                    case SOCKS5-> isAuth ? new Socks5ProxyHandler(inetSocketAddress,
                            username,password): new Socks5ProxyHandler(inetSocketAddress);
                    default -> isAuth ? new HttpProxyHandler(inetSocketAddress,
                            username, password): new HttpProxyHandler(inetSocketAddress);
                };
            }
            if (serverConfig.isHandleSsl()) {
                this.handleSsl = true;
                ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
                X509Certificate caCert;
                PrivateKey caPriKey;
                caCert = CertUtil.loadCert(classLoader.getResourceAsStream("ca.crt"));
                caPriKey = CertUtil.loadPriKey(classLoader.getResourceAsStream("ca_private.der"));
                this.certificateInfo = new CertificateInfo();
                //读取CA证书使用者信息
                certificateInfo.setIssuer(CertUtil.getSubject(caCert));
                //读取CA证书有效时段(server证书有效期超出CA证书的，在手机上会提示证书不安全)
                certificateInfo.setCaNotBefore(caCert.getNotBefore());
                certificateInfo.setCaNotAfter(caCert.getNotAfter());
                //CA私钥用于给动态生成的网站SSL证书签证
                certificateInfo.setCaPriKey(caPriKey);
                //生产一对随机公私钥用于网站SSL证书动态创建
                KeyPair keyPair = CertUtil.genKeyPair();
                certificateInfo.setServerPriKey(keyPair.getPrivate());
                certificateInfo.setServerPubKey(keyPair.getPublic());
            }
            this.channelHandlers.put("httpCodec", new HttpServerCodec(
                    serverConfig.getMaxInitialLineLength(),
                    serverConfig.getMaxHeaderSize(),
                    serverConfig.getMaxChunkSize()));

            this.channelHandlers.put("serverHandle",
                    new HttpProxyServerHandler(this));
            this.bossGroup = new NioEventLoopGroup(serverConfig.getBossGroupThreads());
            this.workerGroup = new NioEventLoopGroup(serverConfig.getWorkerGroupThreads());
            if (proxyInterceptInitializer == null) {
                proxyInterceptInitializer = new HttpProxyInterceptInitializer();
            }
            if (httpProxyExceptionHandle == null) {
                httpProxyExceptionHandle = new HttpProxyExceptionHandle();
            }
        } catch (Exception e) {
            throw new RuntimeException("init context failed",e);
        }
    }

    public ProxyApplicationContext proxyInterceptInitializer(
            HttpProxyInterceptInitializer proxyInterceptInitializer) {
        this.proxyInterceptInitializer = proxyInterceptInitializer;
        return this;
    }

    public ProxyApplicationContext httpProxyExceptionHandle(
            HttpProxyExceptionHandle httpProxyExceptionHandle) {
        this.httpProxyExceptionHandle = httpProxyExceptionHandle;
        return this;
    }


    public void start(int port) {
        start(null, port);
    }

    public void start(String ip, int port) {
        try {
            this.host = ip;
            this.port = port;
            ChannelFuture channelFuture = doBind();
            channelFuture.addListener(future -> {
                if (future.cause() != null) {
                    httpProxyExceptionHandle.startCatch(future.cause());
                }
            });
            channelFuture.channel().closeFuture().sync();
        } catch (Exception e) {
            httpProxyExceptionHandle.startCatch(e);
        } finally {
            close();
        }
    }


//    public CompletionStage<Void> startAsync(String ip, int port) {
//        this.host = ip;
//        this.port = port;
//        ChannelFuture channelFuture = doBind();
//        CompletableFuture<Void> future = new CompletableFuture<>();
//        channelFuture.addListener(start -> {
//            if (start.isSuccess()) {
//                future.complete(null);
//                shutdownHook();
//            } else {
//                future.completeExceptionally(start.cause());
//                close();
//            }
//        });
//        return future;
//    }
    @ChannelHandler.Sharable
    public static class Http2ServerHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
        Http2ServerHandler(){
            this.isSharable();
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) throws Exception {
            // 处理HTTP/2请求
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            // 处理异常
        }
    }

    private ChannelFuture doBind() {
        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .handler(new LoggingHandler(LogLevel.DEBUG))
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) throws Exception {
                        ChannelPipeline pipeline = ch.pipeline();
                        channelHandlers.forEach(pipeline::addLast);
                    }
                });
        return this.host == null ? bootstrap.bind(port) : bootstrap.bind(this.host, port);
    }

    /**
     * 释放资源
     */
    public void close() {
        if (!(proxyGroup.isShutdown() || proxyGroup.isShuttingDown())) {
            proxyGroup.shutdownGracefully();
        }
        if (!(bossGroup.isShutdown() || bossGroup.isShuttingDown())) {
            bossGroup.shutdownGracefully();
        }
        if (!(workerGroup.isShutdown() || workerGroup.isShuttingDown())) {
            workerGroup.shutdownGracefully();
        }

        CertPool.clear();
    }

    /**
     * 注册JVM关闭的钩子以释放资源
     */
    public void shutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(this::close, "Server Shutdown Thread"));
    }

}
