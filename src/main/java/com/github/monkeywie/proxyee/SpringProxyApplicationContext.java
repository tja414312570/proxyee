package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.config.ConfigThreads;
import com.github.monkeywie.proxyee.config.ProxyEEConfiguration;
import com.github.monkeywie.proxyee.config.SSLConfiguration;
import com.github.monkeywie.proxyee.crt.CertUtil;
import com.github.monkeywie.proxyee.exception.HttpProxyExceptionHandle;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Component
public class SpringProxyApplicationContext implements ApplicationContextAware {

    private ApplicationContext applicationContext;
    private HttpProxyServerConfig serverConfig;

    @Autowired
    private ProxyEEConfiguration proxyEEConfiguration;
    private NioEventLoopGroup proxyEventLoopGroup;
    private SslContext clientSslContext;
    private final static InternalLogger log = InternalLoggerFactory.getInstance(HttpProxyServer.class);

    @PostConstruct
    public void init(){
        if (serverConfig == null) {
           serverConfig = new HttpProxyServerConfig();
       }
        ConfigThreads threads = proxyEEConfiguration.getThreads();
        this.proxyEventLoopGroup = new NioEventLoopGroup(threads.getProxy());
       SslContextBuilder contextBuilder = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE);
       // 设置ciphers用于改变 client hello 握手协议指纹
        SSLConfiguration ssl = proxyEEConfiguration.getSsl();
        if (ssl.getChicpers() != null) {
           contextBuilder.ciphers(ssl.getChicpers());
       }
       try {
           this.clientSslContext = contextBuilder.build();
           if (ssl.isHandleSsl()) {
               X509Certificate caCert;
               PrivateKey caPriKey;
               PathMatchingResourcePatternResolver resources = new PathMatchingResourcePatternResolver();
               if (caCertFactory == null) {
                   caCert = CertUtil.loadCert(resources.getResource(ssl.getCaCert()).getInputStream());
                   caPriKey = CertUtil.loadPriKey(resources.getResource(ssl.getCaKey()).getInputStream());
               } else {
                   caCert = caCertFactory.getCACert();
                   caPriKey = caCertFactory.getCAPriKey();
               }
               //读取CA证书使用者信息
               serverConfig.setIssuer(CertUtil.getSubject(caCert));
               //读取CA证书有效时段(server证书有效期超出CA证书的，在手机上会提示证书不安全)
               serverConfig.setCaNotBefore(caCert.getNotBefore());
               serverConfig.setCaNotAfter(caCert.getNotAfter());
               //CA私钥用于给动态生成的网站SSL证书签证
               serverConfig.setCaPriKey(caPriKey);
               //生产一对随机公私钥用于网站SSL证书动态创建
               KeyPair keyPair = CertUtil.genKeyPair();
               serverConfig.setServerPriKey(keyPair.getPrivate());
               serverConfig.setServerPubKey(keyPair.getPublic());
           }
       } catch (Exception e) {
           serverConfig.setHandleSsl(false);
           log.warn("SSL init fail,cause:" + e.getMessage());
       }
       if (proxyInterceptInitializer == null) {
           proxyInterceptInitializer = new HttpProxyInterceptInitializer();
       }
       if (httpProxyExceptionHandle == null) {
           httpProxyExceptionHandle = new HttpProxyExceptionHandle();
       }
   }
    
    @Bean
    public MyServerHandler myServerHandler() {
        return new MyServerHandler();
    }

    @Bean
    public NioEventLoopGroup bossGroup() {
        return new NioEventLoopGroup();
    }

    @Bean
    public NioEventLoopGroup workerGroup() {
        return new NioEventLoopGroup();
    }

    @Bean
    public ServerBootstrap serverBootstrap(NioEventLoopGroup bossGroup,NioEventLoopGroup workerGroup) {
        return new ServerBootstrap()
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<NioServerSocketChannel>() {
                    @Override
                    protected void initChannel(NioServerSocketChannel ch) throws Exception {
                        ChannelPipeline pipeline = ch.pipeline();
                        HttpProxyServerConfig serverConfig = null;
                        pipeline.addLast("httpCodec", new HttpServerCodec(
                                serverConfig.getMaxInitialLineLength(),
                                serverConfig.getMaxHeaderSize(),
                                serverConfig.getMaxChunkSize()));
                    }
                })
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, true);
    }

    @Bean
    public NettyServer nettyServer(ApplicationContext context) {
        return new NettyServer(context.getBean(ServerBootstrap.class));
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
