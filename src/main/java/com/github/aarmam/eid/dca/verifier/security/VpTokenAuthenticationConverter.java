package com.github.aarmam.eid.dca.verifier.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.io.IOException;

public class VpTokenAuthenticationConverter implements AuthenticationConverter {
    private static final ObjectReader OBJECT_READER = new ObjectMapper().readerFor(String.class);
    private static final String VP_TOKEN_FIELD = "vp_token";

    @Override
    public Authentication convert(HttpServletRequest request) {
        String contentType = request.getContentType();
        if (contentType == null || !contentType.toLowerCase().startsWith(MediaType.APPLICATION_JSON_VALUE)) {
            return null;
        }
        try {
            var jsonNode = OBJECT_READER.readTree(request.getReader());
            var vpTokenNode = jsonNode.get(VP_TOKEN_FIELD);
            if (vpTokenNode == null || vpTokenNode.isNull()) {
                throw new BadCredentialsException("Invalid authentication token.");
            }
            String vpToken = vpTokenNode.asText();
            if (vpToken.isBlank()) {
                throw new BadCredentialsException("Invalid authentication token.");
            }
            return new VpAuthenticationRequestToken(vpToken);
        } catch (IOException e) {
            throw new BadCredentialsException("Invalid authentication token.", e);
        }
    }
}
