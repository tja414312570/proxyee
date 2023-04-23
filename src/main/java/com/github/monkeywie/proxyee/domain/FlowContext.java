package com.github.monkeywie.proxyee.domain;

import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.util.ProtoUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * 流程上下文
 */
@Data
public class FlowContext {

    public static final AttributeKey<FlowContext> PROXY_EE_FLOW_CONTEXT = AttributeKey.valueOf("$_PROXY_EE_FLOW_CONTEXT");

    Map<Object,Object> values = new HashMap<>();
    private boolean connected;
    private boolean readied;
    private boolean news;

    private boolean http;

    private HttpProxyInterceptPipeline interceptPipeline;

    private ProtoUtil.RequestProto requestProto;

    public <K,V> void setValue(K key,V value){
        this.values.put(key,value);
    }
    @SuppressWarnings("unchecked")
    public <K,V> V getValue(K key){
        Object o = this.values.get(key);
        return (V) o;
    }
    public static FlowContext get(ChannelHandlerContext ctx) {
        Attribute<FlowContext> attr = ctx.channel().attr(FlowContext.PROXY_EE_FLOW_CONTEXT);
        FlowContext flowContext = attr.get();
        if (flowContext == null) {
            flowContext = new FlowContext();
            attr.set(flowContext);
            flowContext.setNews(true);
            System.err.println("创建上下文:" + System.identityHashCode(flowContext));
        } else {
            flowContext.setNews(false);
            System.err.println("得到存在的上下文:" + System.identityHashCode(flowContext));
        }
        return flowContext;
    }


}
