package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.crt.CertPool;
import com.github.monkeywie.proxyee.crt.CertUtil;
import com.github.monkeywie.proxyee.domain.CertificateInfo;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.handler.ChannelHttpMsgForwardAdapter;
import com.github.monkeywie.proxyee.handler.ChannelTunnelMsgForwardAdapter;
import com.github.monkeywie.proxyee.handler.HttpProxyServerHandler;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.proxy.ProxyConfig;
import com.github.monkeywie.proxyee.server.HttpProxyChannelInitializer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import com.github.monkeywie.proxyee.server.TunnelProxyChannelInitializer;
import com.github.monkeywie.proxyee.server.accept.HttpProxyAcceptHandler;
import com.github.monkeywie.proxyee.server.auth.HttpProxyAuthenticationProvider;
import com.github.monkeywie.proxyee.util.ProtoUtil;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
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
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;
import java.util.function.Supplier;

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
    protected Supplier<ProxyHandler> proxyHandler;
    protected NioEventLoopGroup workerGroup;
    protected HttpProxyAcceptHandler httpProxyAcceptHandler;
    private String host;
    private int port;
    private AddressResolverGroup<? extends SocketAddress> resolver;
    protected boolean handleSsl;

    protected Consumer<Channel> serverChannelInitializer;

    protected HttpProxyChannelInitializer httpProxyChannelInitializer;

    protected TunnelProxyChannelInitializer tunnelProxyChannelInitializer;
    protected Supplier<HttpServerCodec> httpCodecBuilder;

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
                proxyHandler =  ()-> switch (proxyConfig.getProxyType()) {
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
            this.httpCodecBuilder = ()-> new HttpServerCodec(
                    serverConfig.getMaxInitialLineLength(),
                    serverConfig.getMaxHeaderSize(),
                    serverConfig.getMaxChunkSize());
            this.serverChannelInitializer = ch->{
                ch.pipeline().addLast("httpCodec",this.httpCodecBuilder.get());
                ch.pipeline().addLast("serverHandle",new HttpProxyServerHandler(this));
            };
            this.httpProxyChannelInitializer = (ch,proxy)->{
                if (proxyHandler != null) {
                    ch.pipeline().addLast(proxyHandler.get());
                }
                ProtoUtil.RequestProto requestProto = proxy.getRequestProto();
                if (requestProto.getSsl()) {
                    ch.pipeline().addLast(this.clientSslContext.newHandler(ch.alloc(), requestProto.getHost(), requestProto.getPort()));
                }
                ch.pipeline().addLast("httpCodec",new HttpServerCodec(
                        serverConfig.getMaxInitialLineLength(),
                        serverConfig.getMaxHeaderSize(),
                        serverConfig.getMaxChunkSize()) );
                ch.pipeline().addLast("httpMsgForward", new ChannelHttpMsgForwardAdapter(proxy.getClientChannel(), this));
            };
            this.tunnelProxyChannelInitializer = (ch,proxy)->{
                if (proxyHandler != null) {
                    ch.pipeline().addLast(proxyHandler.get());
                }
                ch.pipeline().addLast("tunnelMsgForward",new ChannelTunnelMsgForwardAdapter(proxy.getClientChannel(), this));
            };
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

    public void start(int port) {
        start(null, port);
    }

    public ChannelFuture start(String ip, int port) {
        this.host = ip;
        this.port = port;
        ChannelFuture channelFuture = doBind();
        CountDownLatch latch = new CountDownLatch(1);
        channelFuture.addListener(future -> {
            if (future.cause() != null) {
                httpProxyExceptionHandle.startCatch(future.cause());
            }
            latch.countDown();
        });
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return channelFuture;
    }
    private ChannelFuture doBind() {
        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .handler(new LoggingHandler(LogLevel.DEBUG))
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        serverChannelInitializer.accept(ch);
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
}
