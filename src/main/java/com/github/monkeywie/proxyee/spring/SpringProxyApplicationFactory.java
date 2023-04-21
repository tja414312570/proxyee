package com.github.monkeywie.proxyee.spring;

import org.springframework.boot.ApplicationContextFactory;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;

public class SpringProxyApplicationFactory implements ApplicationContextFactory {
    @Override
    public Class<? extends ConfigurableEnvironment> getEnvironmentType(WebApplicationType webApplicationType) {
        return  SpringProxyStandardEnvironment.class;
    }

    @Override
    public ConfigurableEnvironment createEnvironment(WebApplicationType webApplicationType) {
        return new SpringProxyStandardEnvironment();
    }

    @Override
    public ConfigurableApplicationContext create(WebApplicationType webApplicationType) {
        return createContext();
    }

    private ConfigurableApplicationContext createContext() {
        return new GenericApplicationContext();
    }

}