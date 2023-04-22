package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.config.*;
import com.github.monkeywie.proxyee.crt.CertUtil;
import com.github.monkeywie.proxyee.domain.CertificateInfo;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.handler.ChannelHttpMsgForwardAdapter;
import com.github.monkeywie.proxyee.handler.ChannelTunnelMsgForwardAdapter;
import com.github.monkeywie.proxyee.handler.HttpProxyServerHandler;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.util.ProtoUtil;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.proxy.HttpProxyHandler;
import io.netty.handler.proxy.Socks4ProxyHandler;
import io.netty.handler.proxy.Socks5ProxyHandler;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Component
@Slf4j
@Getter
public class SpringProxyApplicationContext extends ProxyApplicationContext implements ApplicationContextAware{
    protected ApplicationContext applicationContext;
    @Autowired
    protected ProxyEEConfiguration proxyEEConfiguration;
    protected int port;
    protected String host;

    protected boolean running;

    public void init() {
        log.info("初始化proxyee上下文");
        long now = System.currentTimeMillis();
        this.host = proxyEEConfiguration.getHost();
        this.port = proxyEEConfiguration.getPort();
        ConfigThreads threads = proxyEEConfiguration.getThreads();
        this.proxyGroup = new NioEventLoopGroup(threads.getProxy());
        this.bossGroup = new NioEventLoopGroup(threads.getBoss());
        this.workerGroup = new NioEventLoopGroup(threads.getWorker());
        SslContextBuilder contextBuilder = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE);
        // 设置ciphers用于改变 client hello 握手协议指纹
        SSLConfiguration ssl = proxyEEConfiguration.getSsl();
        if (ssl.getChicpers() != null) {
            log.info("初始化ssl chicpers:{}",ssl.getChicpers());
            contextBuilder.ciphers(ssl.getChicpers());
        }
        try {
            this.clientSslContext = contextBuilder.build();
            if (ssl.isHandleSsl()) {
                this.handleSsl = true;
                X509Certificate caCert;
                PrivateKey caPriKey;
                PathMatchingResourcePatternResolver resourceLoader = new DefaultPathMatchingResourcePatternResolver();
                Resource certResource = resourceLoader.getResource(ssl.getCaCert());
                Resource keyResource = resourceLoader.getResource(ssl.getCaKey());
                log.info("初始化ssl证书信息:证书地址{}，密钥地址:{}",certResource.getURL(),keyResource.getURI());
                caCert = CertUtil.loadCert(certResource.getInputStream());
                caPriKey = CertUtil.loadPriKey(keyResource.getInputStream());
                this.certificateInfo = new CertificateInfo();
                //读取CA证书使用者信息
                certificateInfo.setIssuer(CertUtil.getSubject(caCert));
                //读取CA证书有效时段(server证书有效期超出CA证书的，在手机上会提示证书不安全)
                certificateInfo.setCaNotBefore(caCert.getNotBefore());
                certificateInfo.setCaNotAfter(caCert.getNotAfter());
                //CA私钥用于给动态生成的网站SSL证书签证
                certificateInfo.setCaPriKey(caPriKey);
                log.info("证书信息{}",certificateInfo);
                //生产一对随机公私钥用于网站SSL证书动态创建
                KeyPair keyPair = CertUtil.genKeyPair();
                certificateInfo.setServerPriKey(keyPair.getPrivate());
                certificateInfo.setServerPubKey(keyPair.getPublic());
            }
        } catch (Exception e) {
            log.error("SSL init fail,cause:" + e.getMessage(),e);
        }
        CodecConfiguration codec = proxyEEConfiguration.getCodec();
        this.httpCodecBuilder = ()-> new HttpServerCodec(
                codec.getMaxInitialLineLength(),
                codec.getMaxHeaderSize(),
                codec.getMaxChunkSize());
        //服务渠道初始化工具
        this.serverChannelInitializer = ch -> {
            ch.pipeline().addLast("httpCodec", this.httpCodecBuilder.get());
            ch.pipeline().addLast("serverHandle", new HttpProxyServerHandler(this));
        };
        this.httpProxyChannelInitializer = (ch,proxy)->{
            if (proxyHandler != null) {
                ch.pipeline().addLast(proxyHandler.get());
            }
            ProtoUtil.RequestProto requestProto = proxy.getRequestProto();
            if (requestProto.getSsl()) {
                ch.pipeline().addLast(this.clientSslContext.newHandler(ch.alloc(), requestProto.getHost(), requestProto.getPort()));
            }
            ch.pipeline().addLast("httpCodec",new HttpClientCodec(
                    codec.getMaxInitialLineLength(),
                    codec.getMaxHeaderSize(),
                    codec.getMaxChunkSize()) );
            ch.pipeline().addLast("proxyClientHandle", new ChannelHttpMsgForwardAdapter(proxy.getClientChannel(), this));
        };
        this.tunnelProxyChannelInitializer = (ch,proxy)->{
            if (proxyHandler != null) {
                ch.pipeline().addLast(proxyHandler.get());
            }
            ch.pipeline().addLast(new ChannelTunnelMsgForwardAdapter(proxy.getClientChannel(), this));
        };
        if (proxyInterceptInitializer == null) {
            proxyInterceptInitializer = new HttpProxyInterceptInitializer();
        }
        if (httpProxyExceptionHandle == null) {
            httpProxyExceptionHandle = new HttpProxyExceptionHandle();
        }
        //上游代理
        UpstreamConfiguration upstream = proxyEEConfiguration.getUpstream();
        if (upstream != null) {
            InetSocketAddress inetSocketAddress = new InetSocketAddress(upstream.getHost(),
                    upstream.getPort());
            boolean isAuth = upstream.getUsername()!= null && upstream.getPassword() != null;
            proxyHandler =  ()-> switch (StringUtils.lowerCase(upstream.getType())) {
                case "socket4"-> new Socks4ProxyHandler(inetSocketAddress);
                case "socket5"-> isAuth ? new Socks5ProxyHandler(inetSocketAddress,
                                upstream.getUsername(), upstream.getPassword()): new Socks5ProxyHandler(inetSocketAddress);
                default -> isAuth ? new HttpProxyHandler(inetSocketAddress,
                        upstream.getUsername(), upstream.getPassword()): new HttpProxyHandler(inetSocketAddress);
            };
        }
        log.info("初始化proxyee耗时:{}ms",System.currentTimeMillis()-now);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
