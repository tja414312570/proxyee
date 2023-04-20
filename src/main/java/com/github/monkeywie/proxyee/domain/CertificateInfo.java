package com.github.monkeywie.proxyee.domain;

import lombok.Data;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

@Data
public class CertificateInfo {
    private String issuer;
    private Date caNotBefore;
    private Date caNotAfter;
    private PrivateKey caPriKey;
    private PrivateKey serverPriKey;
    private PublicKey serverPubKey;
}
