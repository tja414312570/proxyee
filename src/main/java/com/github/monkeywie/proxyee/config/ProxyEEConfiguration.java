package com.github.monkeywie.proxyee.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@ConfigurationProperties(prefix = "spring.proxyee")
@Data
public class ProxyEEConfiguration {
    private String host;
    private int port;

    @NestedConfigurationProperty
    private ConfigThreads threads;
    @NestedConfigurationProperty
    private SSLConfiguration ssl;
    @NestedConfigurationProperty
    private AuthConfiguration auth;
    @NestedConfigurationProperty
    private UpstreamConfiguration upstream;

}
