package com.github.aarmam.eid.dca.verifier.security;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
public class VpAuthentication extends AbstractAuthenticationToken {
    private final VpUserEntity vpUserEntity;

    public VpAuthentication(VpUserEntity vpUserEntity, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        super.setAuthenticated(true);
        this.vpUserEntity = vpUserEntity;
    }

    @Override
    public VpUserEntity getPrincipal() {
        return vpUserEntity;
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
