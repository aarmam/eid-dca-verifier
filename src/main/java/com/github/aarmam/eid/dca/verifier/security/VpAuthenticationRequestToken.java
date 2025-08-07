package com.github.aarmam.eid.dca.verifier.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;

public class VpAuthenticationRequestToken extends AbstractAuthenticationToken {

    private final String vpToken;

    public VpAuthenticationRequestToken(String vpToken) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.vpToken = vpToken;
    }

    @Override
    public Object getCredentials() {
        return vpToken;
    }

    @Override
    public Object getPrincipal() {
        return vpToken;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        Assert.isTrue(!authenticated, "Cannot set this token to trusted");
        super.setAuthenticated(false);
    }
}
