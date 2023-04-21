package com.github.monkeywie.proxyee.crt;

import com.github.monkeywie.proxyee.domain.CertificateInfo;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;

public class CertPool {

    private static Map<Integer, Map<String, X509Certificate>> certCache = new WeakHashMap<>();

    public static X509Certificate getCert(Integer port, String host, CertificateInfo certificateInfo)
            throws Exception {
        X509Certificate cert = null;
        if (host != null) {
            Map<String, X509Certificate> portCertCache = certCache.get(port);
            if (portCertCache == null) {
                portCertCache = new HashMap<>();
                certCache.put(port, portCertCache);
            }
            String key = host.trim().toLowerCase();
            if (portCertCache.containsKey(key)) {
                return portCertCache.get(key);
            } else {
                cert = CertUtil.genCert(certificateInfo.getIssuer(), certificateInfo.getCaPriKey(),
                        certificateInfo.getCaNotBefore(), certificateInfo.getCaNotAfter(),
                        certificateInfo.getServerPubKey(), key);
                portCertCache.put(key, cert);
            }
        }
        return cert;
    }

    public static void clear() {
        certCache.clear();
    }
}
