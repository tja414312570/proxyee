package com.github.monkeywie.proxyee.consts;

import io.netty.handler.codec.http.HttpResponseStatus;

public class HttpsResponse {
    //http代理隧道握手成功
    public final static HttpResponseStatus SUCCESS = new HttpResponseStatus(200,
            "Connection established");
    public final static HttpResponseStatus UNAUTHORIZED = new HttpResponseStatus(407,
            "Unauthorized");
}
