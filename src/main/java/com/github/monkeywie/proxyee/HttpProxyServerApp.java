package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.handler.HttpProxyServerHandler;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpServerCodec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

/**
 * @Author LiWei
 * @Description
 * @Date 2019/9/23 17:30
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class HttpProxyServerApp {
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(HttpProxyServerApp.class);
        application.setWebApplicationType(WebApplicationType.NONE);
        application.run(args);
//        System.out.println("start proxy server");
//        int port = 9999;
//        if (args.length > 0) {
//            port = Integer.valueOf(args[0]);
//        }
//        new HttpProxyServer().start(port);
    }

}
