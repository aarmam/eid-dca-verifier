package com.github.aarmam.eid.dca.verifier;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

import java.security.Security;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class VerifierApplication {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        SpringApplication.run(VerifierApplication.class, args);
    }

}
