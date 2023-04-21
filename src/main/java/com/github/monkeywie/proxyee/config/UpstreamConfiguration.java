package com.github.monkeywie.proxyee.config;

import lombok.Data;

@Data
public class UpstreamConfiguration {
    private String type = "http";
    private String host;
    private int port;
    private String password;
    private String username;
}
