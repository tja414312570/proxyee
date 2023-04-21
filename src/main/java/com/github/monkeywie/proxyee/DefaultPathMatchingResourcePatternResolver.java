package com.github.monkeywie.proxyee;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;

public class DefaultPathMatchingResourcePatternResolver extends PathMatchingResourcePatternResolver {
    @Override
    public Resource getResource(String location) {
        return getResource(location,false);
    }
    public Resource getResource(String location,boolean only) {
        Resource[] resources = new Resource[0];
        try {
            resources = super.getResources(location);
            if(ArrayUtils.isEmpty(resources)){
                throw new RuntimeException("could not found any resource at "+location);
            }
            if(resources.length >1 && only){
                throw new RuntimeException("except one resource but found "+resources.length);
            }
            return resources[0];
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
