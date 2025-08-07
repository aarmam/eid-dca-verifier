package com.github.aarmam.eid.dca.verifier.security;

import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.AuthTokenException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.www.NonceExpiredException;

@RequiredArgsConstructor
public class VpTokenAuthenticationProvider implements AuthenticationProvider {
    private final ChallengeNonceStore challengeNonceStore;
    private final VpTokenValidator vpTokenValidator;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            final ChallengeNonce challengeNonce = challengeNonceStore.getAndRemove();
            final VpUserEntity eidUser = vpTokenValidator.validate(authentication.getCredentials(), challengeNonce.getBase64EncodedNonce());
            return new VpAuthentication(eidUser, AuthorityUtils.NO_AUTHORITIES);
        } catch (AuthTokenException e) {
            throw new NonceExpiredException("Nonce not found or expired.", e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return VpAuthenticationRequestToken.class.isAssignableFrom(authentication);
    }
}
