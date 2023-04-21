package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.spring.SpringProxyApplicationFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

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
        application.setApplicationContextFactory(new SpringProxyApplicationFactory());
        application.run(args);
//        System.out.println("start proxy server");
//        int port = 9999;
//        if (args.length > 0) {
//            port = Integer.valueOf(args[0]);
//        }
//        new HttpProxyServer().start(port);
    }

}
