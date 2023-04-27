package com.github.monkeywie.proxyee.domain;

import com.github.monkeywie.proxyee.ProxyApplicationContext;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.util.ProtoUtil;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;
import lombok.Data;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 流程上下文
 */
@Data
public class FlowContext {

    public static final AttributeKey<FlowContext> PROXY_EE_FLOW_CONTEXT = AttributeKey.valueOf("$_PROXY_EE_FLOW_CONTEXT");

    private boolean connected;

    private boolean remoteConnected;
    private boolean readied;
    private boolean news;

    private boolean http;

    private HttpProxyInterceptPipeline interceptPipeline;

    private ProtoUtil.RequestProto requestProto;

    private List<Object> messageList;
//    private ChannelHandlerContext channelHandlerContext;

    private Channel clientChannel;
    private Channel proxyChannel;
    private ProxyApplicationContext applicationContext;
    private final Map<Object,Object> attributes = new HashMap<>();
    private boolean proxySSl;

    private boolean proxySslCompleted;


    @SuppressWarnings("unchecked")
    public <T> T getAttribute(Object key) {
        return (T) attributes.get(key);
    }

    public <T> void setAttribute(Object key, T value) {
        attributes.put(key,value);
    }

    public static FlowContext get(ChannelHandlerContext ctx, ProxyApplicationContext context) {
        Attribute<FlowContext> attr = ctx.channel().attr(FlowContext.PROXY_EE_FLOW_CONTEXT);
        FlowContext flowContext = attr.get();
        if (flowContext == null) {
            flowContext = new FlowContext();
            attr.set(flowContext);
            flowContext.setNews(true);
            flowContext.setApplicationContext(context);
            flowContext.clientChannel = ctx.channel();
        } else {
            flowContext.setNews(false);
        }
      return flowContext;
    }
    public void bindProxyChannel(Channel channel) {
        channel.attr(FlowContext.PROXY_EE_FLOW_CONTEXT).set(this);
        this.proxyChannel = channel;
    }
    public static FlowContext get(ChannelHandlerContext ctx) {
        return get(ctx.channel());
    }
    public static FlowContext get(Channel channel) {
        Attribute<FlowContext> attr = channel.attr(FlowContext.PROXY_EE_FLOW_CONTEXT);
        FlowContext flowContext = attr.get();
        if (flowContext == null) {
            throw new RuntimeException("没有上下文");
        } else {
            flowContext.setNews(false);
        }
        return flowContext;
    }

}
