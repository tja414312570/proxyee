package com.github.monkeywie.proxyee;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Import;

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
        application.run(args);
//        System.out.println("start proxy server");
//        int port = 9999;
//        if (args.length > 0) {
//            port = Integer.valueOf(args[0]);
//        }
//        new HttpProxyServer().start(port);
    }

}
