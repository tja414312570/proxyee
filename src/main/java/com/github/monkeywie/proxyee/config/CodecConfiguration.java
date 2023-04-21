package com.github.monkeywie.proxyee.config;

import io.netty.handler.codec.http.HttpObjectDecoder;
import lombok.Data;

@Data
public class CodecConfiguration {
    private int maxInitialLineLength = HttpObjectDecoder.DEFAULT_MAX_INITIAL_LINE_LENGTH;
    private int maxHeaderSize = HttpObjectDecoder.DEFAULT_MAX_HEADER_SIZE;
    private int maxChunkSize = HttpObjectDecoder.DEFAULT_MAX_CHUNK_SIZE;
}
