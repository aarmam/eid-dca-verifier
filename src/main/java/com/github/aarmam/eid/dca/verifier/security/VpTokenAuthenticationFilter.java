package com.github.aarmam.eid.dca.verifier.security;

import eu.webeid.security.challenge.ChallengeNonceStore;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.HttpMessageConverterAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

public class VpTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public static final String DEFAULT_LOGIN_PROCESSING_URL = "/login/vp";

    public VpTokenAuthenticationFilter(ChallengeNonceStore challengeNonceStore, VpTokenValidator vpTokenValidator) {
        super(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, DEFAULT_LOGIN_PROCESSING_URL));
        setSessionAuthenticationStrategy(new SessionFixationProtectionStrategy());
        setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        setAuthenticationConverter(new VpTokenAuthenticationConverter());
        setAuthenticationManager(new ProviderManager(new VpTokenAuthenticationProvider(challengeNonceStore, vpTokenValidator)));
        setAuthenticationFailureHandler(new VpTokenAuthenticationFailureHandler());
        setAuthenticationSuccessHandler(new HttpMessageConverterAuthenticationSuccessHandler());
    }
}