package ru.sem.spring.auth_service.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ru.sem.spring.auth_service.service.exception.CannotSignJwtException;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

@Component
public final class JwtServiceBase implements JwtService {
//    private String secret;
//    @Value("${jwt.secret}")
// todo: почему-то не подтягивается секрет из yml файла, позже убери
    private final String secret = "my-very-very-secure-secret-key-at-least-256-bits-long";


    private static final Logger LOGGER = LoggerFactory.getLogger(JwtServiceBase.class);

    private static final String ISSUER = "auth-service";
    private static final Charset CHARSET = StandardCharsets.UTF_8;

    @PostConstruct
    public void verifySecret() {
        if (secret == null || secret.getBytes(CHARSET).length < 32) {
            LOGGER.error("Invalid secret");
            throw new IllegalArgumentException("Invalid secret");
        }
        LOGGER.debug("Valid secret");
    }

    @Override
    public String generateToken(Map<String, Object> claims, String subject, Duration ttl)
            throws CannotSignJwtException {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJwt = getSignedJWT(claims, subject, ttl, header);
        try {
            signedJwt.sign(new MACSigner(secret.getBytes(CHARSET)));
        } catch (JOSEException e) {
            LOGGER.error("Failed to sign token {}", signedJwt);
            throw new CannotSignJwtException("Failed to sign token");
        }

        return signedJwt.serialize();
    }

    private static SignedJWT getSignedJWT(Map<String, Object> claims, String subject, Duration ttl, JWSHeader header) {
        var now = Instant.now();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(ISSUER)
                .expirationTime(Date.from(now.plus(ttl)))
                .issueTime(Date.from(now));

        if (!claims.containsKey("type")) {
            claims.put("type", ttl.toMinutes() > 60 ? "REFRESH" : "ACCESS");
        }

        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }

        if (!claims.containsKey("type")) {
            claims.put("type", ttl.toMinutes() > 60 ? "REFRESH" : "ACCESS");
        }
        JWTClaimsSet claimsSet = builder.build();
        SignedJWT signedJwt = new SignedJWT(header, claimsSet);
        return signedJwt;
    }

    private static final Duration CLOCK_SKEW = Duration.ofSeconds(15);

    @Override
    public boolean isValid(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);

            if (!jwt.verify(new MACVerifier(secret.getBytes(CHARSET)))) {
                // todo: убери потом, токен в лог писать небезопасно
                LOGGER.error("Invalid JWT signature for token: {}", token);
                return false;
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Instant now = Instant.now();
            return claims.getIssuer().equals(ISSUER) &&
                    now.plus(CLOCK_SKEW).isAfter(claims.getIssueTime().toInstant()) &&
                    now.minus(CLOCK_SKEW).isBefore(claims.getExpirationTime().toInstant());
        } catch (ParseException | JOSEException e) {
            LOGGER.error("Invalid token {}", e.getMessage());
            return false;
        }
    }

    @Override
    public Optional<String> extractSubject(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            return Optional.ofNullable(jwt.getJWTClaimsSet().getSubject());
        } catch (Exception e) {
            LOGGER.error("Cannot extract subject from token");
            return Optional.empty();
        }
    }


    @Override
    public Optional<Map<String, Object>> extractAllClaims(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            return Optional.ofNullable(jwt.getJWTClaimsSet().getClaims());
        } catch (ParseException e) {
            LOGGER.error("Cannot extract all claims from token");
            return Optional.empty();
        }
    }
}
