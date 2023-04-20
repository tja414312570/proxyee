package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.intercept.common.CertDownIntercept;
import com.github.monkeywie.proxyee.intercept.common.FullRequestIntercept;
import com.github.monkeywie.proxyee.intercept.common.FullResponseIntercept;
import com.github.monkeywie.proxyee.proxy.ProxyConfig;
import com.github.monkeywie.proxyee.proxy.ProxyType;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import com.github.monkeywie.proxyee.util.HttpUtil;
import io.netty.handler.codec.http.*;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.Charset;
import java.util.LinkedHashSet;
import java.util.Set;

public class InterceptFullResponseProxyServer {

    public static void main(String[] args) throws Exception {
        HttpProxyServerConfig config = new HttpProxyServerConfig();
        config.setHandleSsl(true);
        // 设置Ciphers 用于改变 Client Hello 握手协议指纹
        Set<String> defaultCiphers = new LinkedHashSet<String>();
        defaultCiphers.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        defaultCiphers.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        defaultCiphers.add("TLS_RSA_WITH_AES_128_CBC_SHA");
        defaultCiphers.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
        defaultCiphers.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        config.setCiphers(defaultCiphers);
        new HttpProxyServer()
                .proxyConfig(new ProxyConfig(ProxyType.HTTP,"127.0.0.1",7890))
                .serverConfig(config)
                .proxyInterceptInitializer(new HttpProxyInterceptInitializer() {
                    @Override
                    public void init(HttpProxyInterceptPipeline pipeline) {
                        pipeline.addLast(new CertDownIntercept());
                        pipeline.addLast(new FullRequestIntercept(){

                            @Override
                            public boolean match(HttpRequest httpRequest, HttpProxyInterceptPipeline pipeline) {
                                return true;
//                                return httpRequest.uri().toLowerCase().contains("chat.openai.com");
                            }

                            @Override
                            public void handleRequest(FullHttpRequest httpRequest, HttpProxyInterceptPipeline pipeline) {
                                System.err.println("========================请求");
                                System.err.println(httpRequest);
                            }
                        });
                        pipeline.addLast(new FullResponseIntercept() {

                            @Override
                            public boolean match(HttpRequest httpRequest, HttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
                                //在匹配到百度首页时插入js
                                return true;
//                                return httpRequest.uri().toLowerCase().contains("chat.openai.com");
                            }

                            @Override
                            public void handleResponse(HttpRequest httpRequest, FullHttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
                                System.err.println("========================响应"+httpResponse.status());
                                System.err.println(httpRequest.toString());
                                //打印原始响应信息
                                System.out.println(httpResponse.toString());
                                System.out.println(httpResponse.content().toString(Charset.defaultCharset()));
                                //修改响应头和响应体
                                HttpHeaders headers = httpResponse.headers();
                                Set<String> names = headers.names();
//                                String s = headers.get("Set-Cookie");
//                                if(StringUtils.isNotEmpty(s)){
//                                    headers.set("set-cookie",s);
//                                    headers.remove("Set-Cookie");
//                                }
//                                names.forEach(item->{
//                                    System.err.println(item+"===>"+headers.get(item));
////                                    String value = headers.get(item);
////                                    headers.remove(item);
////                                    headers.set(item.toLowerCase(),value);
//                                });
                                headers.set("handel", "edit head");
//                    /*int index = ByteUtil.findText(httpResponse.content(), "<head>");
//                    ByteUtil.insertText(httpResponse.content(), index, "<script>alert(1)</script>");*/
//                                httpResponse.content().writeBytes("<script>alert('hello proxyee')</script>".getBytes());
                            }
                        });
                    }
                })
                .start(9999);
    }
}
