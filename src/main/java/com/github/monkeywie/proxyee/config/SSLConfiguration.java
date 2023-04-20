package com.github.monkeywie.proxyee.config;

import lombok.Data;

import java.util.List;

@Data
public class SSLConfiguration {
    private List<String> chicpers;
    private boolean handleSsl;
    private String caCert;
    private String caKey;
}
