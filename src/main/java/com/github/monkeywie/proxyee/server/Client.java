package com.github.monkeywie.proxyee.server;

import com.github.monkeywie.proxyee.config.ProxyEEConfiguration;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

@Component
public class Client {
    private ProxyEEConfiguration proxyEEConfiguration;
    @PostConstruct
    public void init(){
        System.err.println(proxyEEConfiguration);
    }
}
