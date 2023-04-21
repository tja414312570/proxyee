package com.github.monkeywie.proxyee;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class HttpProxyServerApp {
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(HttpProxyServerApp.class);
        application.run(args);
    }
}
