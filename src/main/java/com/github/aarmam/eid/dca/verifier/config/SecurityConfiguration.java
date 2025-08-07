package com.github.aarmam.eid.dca.verifier.config;

import com.github.aarmam.eid.dca.verifier.security.SessionBackedChallengeNonceStore;
import com.github.aarmam.eid.dca.verifier.security.VpAuthenticationChallengeNonceFilter;
import com.github.aarmam.eid.dca.verifier.security.VpTokenAuthenticationFilter;
import com.github.aarmam.eid.dca.verifier.security.VpTokenValidator;
import eu.webeid.security.challenge.ChallengeNonceStore;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    @Value("${dca.verifier.nonce-ttl:5m}")
    private Duration challengeNonceTtl;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ChallengeNonceStore challengeNonceStore, VpTokenValidator vpTokenValidator) throws Exception {
        return http
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        .requestMatchers("/login", "/css/**", "/assets/**").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new VpAuthenticationChallengeNonceFilter(challengeNonceStore, challengeNonceTtl), AuthorizationFilter.class)
                .addFilterBefore(new VpTokenAuthenticationFilter(challengeNonceStore, vpTokenValidator), BasicAuthenticationFilter.class)
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .build();
    }

    @Bean
    public VpTokenValidator vpTokenValidator(List<X509Certificate> trustedRootCAs,
                                             @Value("${dca.verifier.origin:https://verifier.localhost:8443}") String origin) {
        return new VpTokenValidator(trustedRootCAs, origin);
    }

    @Bean
    public ChallengeNonceStore challengeNonceStore(ObjectFactory<HttpSession> httpSessionFactory) {
        return new SessionBackedChallengeNonceStore(httpSessionFactory);
    }

    @Bean
    public List<X509Certificate> trustedRootCAs(SslBundles sslBundles) throws KeyStoreException {
        KeyStore trustStore = sslBundles.getBundle("issuer-ca").getStores().getTrustStore();
        List<X509Certificate> issuerRootCAs = new ArrayList<>();
        Enumeration<String> aliases = trustStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate certificate = (X509Certificate) trustStore.getCertificate(alias);
            if (certificate != null) {
                issuerRootCAs.add(certificate);
            }
        }
        return issuerRootCAs;
    }
}
