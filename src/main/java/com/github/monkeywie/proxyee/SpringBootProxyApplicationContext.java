package com.github.monkeywie.proxyee;

import io.netty.channel.ChannelFuture;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@Getter
public class SpringBootProxyApplicationContext extends SpringProxyApplicationContext implements SmartLifecycle {
    private void startDaemonAwaitThread(ChannelFuture channelFuture) {
        Thread awaitThread = new Thread("server") {
            @Override
            public void run() {
                try {
                    channelFuture.channel().closeFuture().sync();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        };
        awaitThread.setContextClassLoader(getClass().getClassLoader());
        awaitThread.setDaemon(false);
        awaitThread.start();
    }
    @Override
    public void start() {
        long now = System.currentTimeMillis();
        this.init();
        ChannelFuture channelFuture = super.start(this.host, this.port);
        startDaemonAwaitThread(channelFuture);
        this.running = true;
        log.info("proxy ee启动完成在{}ms，地址:{}:{}",(System.currentTimeMillis()-now),this.host,this.port);
    }

    @Override
    public void stop() {
        log.info("关闭proxy");
        if(this.running){
            super.close();
            this.running = false;
        }
    }

    @Override
    public boolean isRunning() {
        return this.running;
    }
}
