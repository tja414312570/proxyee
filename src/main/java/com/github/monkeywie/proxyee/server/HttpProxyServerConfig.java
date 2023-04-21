package com.github.monkeywie.proxyee.server;

import com.github.monkeywie.proxyee.proxy.ProxyConfig;
import com.github.monkeywie.proxyee.server.accept.HttpProxyAcceptHandler;
import com.github.monkeywie.proxyee.server.auth.HttpProxyAuthenticationProvider;
import io.netty.channel.EventLoopGroup;
import io.netty.handler.codec.http.HttpObjectDecoder;
import io.netty.handler.ssl.SslContext;
import io.netty.resolver.AddressResolverGroup;
import io.netty.resolver.DefaultAddressResolverGroup;
import lombok.Data;

import java.net.SocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

@Data
public class HttpProxyServerConfig {
    private int bossGroupThreads;
    private int workerGroupThreads;
    private int proxyGroupThreads;
    private boolean handleSsl;

    private ProxyConfig proxyConfig;
    private HttpProxyAcceptHandler httpProxyAcceptHandler;
    private HttpProxyAuthenticationProvider authenticationProvider;
    private final AddressResolverGroup<? extends SocketAddress> resolver;
    private Iterable<String> ciphers;
    private int maxInitialLineLength = HttpObjectDecoder.DEFAULT_MAX_INITIAL_LINE_LENGTH;
    private int maxHeaderSize = HttpObjectDecoder.DEFAULT_MAX_HEADER_SIZE;
    private int maxChunkSize = HttpObjectDecoder.DEFAULT_MAX_CHUNK_SIZE;

    public HttpProxyServerConfig() {
        this(DefaultAddressResolverGroup.INSTANCE);
    }

    public HttpProxyServerConfig(final AddressResolverGroup<? extends SocketAddress> resolver) {
        this.resolver = resolver;
    }

    private HttpProxyServerConfig(Builder builder) {
        this.bossGroupThreads = builder.bossGroupThreads;
        this.workerGroupThreads = builder.workerGroupThreads;
        this.proxyGroupThreads = builder.proxyGroupThreads;
        this.handleSsl = builder.handleSsl;
        this.httpProxyAcceptHandler = builder.httpProxyAcceptHandler;
        this.resolver = builder.resolver;
        this.maxInitialLineLength = builder.maxInitialLineLength;
        this.maxHeaderSize = builder.maxHeaderSize;
        this.maxChunkSize = builder.maxChunkSize;
    }

    public static class Builder {
        private SslContext clientSslCtx;
        private String issuer;
        private Date caNotBefore;
        private Date caNotAfter;
        private PrivateKey caPriKey;
        private PrivateKey serverPriKey;
        private PublicKey serverPubKey;
        private EventLoopGroup proxyLoopGroup;
        private int bossGroupThreads;
        private int workerGroupThreads;
        private int proxyGroupThreads;
        private boolean handleSsl;
        private HttpProxyAcceptHandler httpProxyAcceptHandler;
        private HttpProxyAuthenticationProvider authenticationProvider;
        private final AddressResolverGroup<? extends SocketAddress> resolver;
        private int maxInitialLineLength = HttpObjectDecoder.DEFAULT_MAX_INITIAL_LINE_LENGTH;
        private int maxHeaderSize = HttpObjectDecoder.DEFAULT_MAX_HEADER_SIZE;
        private int maxChunkSize = HttpObjectDecoder.DEFAULT_MAX_CHUNK_SIZE;

        public Builder() {
            this(DefaultAddressResolverGroup.INSTANCE);
        }

        public Builder(final AddressResolverGroup<? extends SocketAddress> resolver) {
            this.resolver = resolver;
        }

        public Builder setClientSslCtx(SslContext clientSslCtx) {
            this.clientSslCtx = clientSslCtx;
            return this;
        }

        public Builder setIssuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder setCaNotBefore(Date caNotBefore) {
            this.caNotBefore = caNotBefore;
            return this;
        }

        public Builder setCaNotAfter(Date caNotAfter) {
            this.caNotAfter = caNotAfter;
            return this;
        }

        public Builder setCaPriKey(PrivateKey caPriKey) {
            this.caPriKey = caPriKey;
            return this;
        }

        public Builder setServerPriKey(PrivateKey serverPriKey) {
            this.serverPriKey = serverPriKey;
            return this;
        }

        public Builder setServerPubKey(PublicKey serverPubKey) {
            this.serverPubKey = serverPubKey;
            return this;
        }

        public Builder setProxyLoopGroup(EventLoopGroup proxyLoopGroup) {
            this.proxyLoopGroup = proxyLoopGroup;
            return this;
        }

        public Builder setHandleSsl(boolean handleSsl) {
            this.handleSsl = handleSsl;
            return this;
        }

        public Builder setBossGroupThreads(int bossGroupThreads) {
            this.bossGroupThreads = bossGroupThreads;
            return this;
        }

        public Builder setWorkerGroupThreads(int workerGroupThreads) {
            this.workerGroupThreads = workerGroupThreads;
            return this;
        }

        public Builder setProxyGroupThreads(int proxyGroupThreads) {
            this.proxyGroupThreads = proxyGroupThreads;
            return this;
        }

        public Builder setHttpProxyAcceptHandler(final HttpProxyAcceptHandler httpProxyAcceptHandler) {
            this.httpProxyAcceptHandler = httpProxyAcceptHandler;
            return this;
        }

        public Builder setAuthenticationProvider(final HttpProxyAuthenticationProvider authenticationProvider) {
            this.authenticationProvider = authenticationProvider;
            return this;
        }

        public Builder setMaxInitialLineLength(int maxInitialLineLength) {
            this.maxInitialLineLength = maxInitialLineLength;
            return this;
        }

        public Builder setMaxHeaderSize(int maxHeaderSize) {
            this.maxHeaderSize = maxHeaderSize;
            return this;
        }

        public Builder setMaxChunkSize(int maxChunkSize) {
            this.maxChunkSize = maxChunkSize;
            return this;
        }

        public HttpProxyServerConfig build() {
            HttpProxyServerConfig config = new HttpProxyServerConfig(this);
            return config;
        }
    }
}
