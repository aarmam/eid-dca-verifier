package com.github.aarmam.eid.dca.verifier.security;

import lombok.Builder;

import java.security.cert.X509Certificate;

@Builder
public record VpUserEntity(String name, String idCode, X509Certificate authCertificate,
                           X509Certificate signCertificate) {

}
