package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.config.ProxyEEConfiguration;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpServerCodec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
public class SpringProxyServer {
    @Autowired
    private ProxyEEConfiguration proxyEEConfiguration;
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
}
