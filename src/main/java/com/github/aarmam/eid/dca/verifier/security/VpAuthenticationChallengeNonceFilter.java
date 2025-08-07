package com.github.aarmam.eid.dca.verifier.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import eu.webeid.security.challenge.ChallengeNonceGeneratorBuilder;
import eu.webeid.security.challenge.ChallengeNonceStore;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

public class VpAuthenticationChallengeNonceFilter extends OncePerRequestFilter {
    private static final String DEFAULT_LOGIN_INIT_URL = "/login/vp/challenge";
    public static final String NONCE = "nonce";
    private final RequestMatcher loginInitMatcher = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, DEFAULT_LOGIN_INIT_URL);
    private final ChallengeNonceGenerator nonceGenerator;
    private final ObjectWriter objectMapper = new ObjectMapper().writerFor(Map.class);

    public VpAuthenticationChallengeNonceFilter(ChallengeNonceStore challengeNonceStore, Duration challengeNonceTtl) {
        nonceGenerator = new ChallengeNonceGeneratorBuilder()
                .withNonceTtl(challengeNonceTtl)
                .withChallengeNonceStore(challengeNonceStore)
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (loginInitMatcher.matches(request)) {
            String nonce = nonceGenerator.generateAndStoreNonce().getBase64EncodedNonce();
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_OK);
            objectMapper.writeValue(response.getWriter(), Map.of(NONCE, nonce));
        } else {
            filterChain.doFilter(request, response);
        }
    }
}