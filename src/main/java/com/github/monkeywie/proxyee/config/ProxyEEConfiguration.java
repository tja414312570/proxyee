package com.github.monkeywie.proxyee.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "spring.proxyee")
@Data
public class ProxyEEConfiguration {
    private String host;
    private int port;
}
