package com.github.monkeywie.proxyee.config;


import lombok.Data;

@Data
public class ConfigThreads{
    private int worker;
    private int boss;
    private int proxy;
}
