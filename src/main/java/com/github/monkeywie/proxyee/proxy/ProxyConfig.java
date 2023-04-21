package com.github.monkeywie.proxyee.proxy;

import lombok.Data;

import java.io.Serializable;

@Data
public class ProxyConfig implements Serializable {

    private static final long serialVersionUID = 1531104384359036231L;

    private ProxyType proxyType;
    private String host;
    private int port;
    private String username;
    private String password;

    public ProxyConfig() {
    }

    public ProxyConfig(ProxyType proxyType, String host, int port) {
        this.proxyType = proxyType;
        this.host = host;
        this.port = port;
    }

    public ProxyConfig(ProxyType proxyType, String host, int port, String user, String pwd) {
        this.proxyType = proxyType;
        this.host = host;
        this.port = port;
        this.username = user;
        this.password = pwd;
    }
}
