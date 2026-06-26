package io.mcpmesh.auth.manager.keycloak;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

/**
 * Mints the short-lived ES256 client-secret JWT that "Sign in with Apple"
 * requires in place of a static OAuth client secret.
 *
 * <p>Apple's OIDC token endpoint will not accept a fixed client secret; the
 * relying party must present a JWT signed with the EC private key downloaded
 * from the Apple Developer portal (the {@code .p8} file). The JWT carries:
 * <ul>
 *   <li>header: {@code alg=ES256}, {@code kid=<Key ID>}, {@code typ=JWT}</li>
 *   <li>{@code iss = <Team ID>}</li>
 *   <li>{@code sub = <Services ID>} (the OIDC client_id)</li>
 *   <li>{@code aud = https://appleid.apple.com}</li>
 *   <li>{@code iat = now}, {@code exp = now + 150d}</li>
 * </ul>
 *
 * <p>Apple caps {@code exp} at 6 months; we use 150 days as a safe margin. The
 * secret therefore EXPIRES — {@code IdentityProvidersBootstrap} re-mints it on
 * boot and on a scheduled cron so a long-running pod never serves a stale JWT.
 */
@Component
public class AppleClientSecretSigner {

    static final String APPLE_AUDIENCE = "https://appleid.apple.com";
    /** Days until the minted JWT expires. Apple's hard cap is 6 months. */
    static final long EXPIRY_DAYS = 150;

    /**
     * Mints an Apple client-secret JWT from the given credentials.
     *
     * @throws IllegalStateException if the private key can't be parsed or the
     *                               JWT can't be signed.
     */
    public String mint(PlatformOAuthProperties.AppleProvider creds) {
        if (creds == null || !creds.isConfigured()) {
            throw new IllegalStateException("Apple credentials not configured");
        }
        ECPrivateKey privateKey = parsePrivateKey(creds.privateKey());

        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer(creds.teamId())
            .subject(creds.servicesId())
            .audience(APPLE_AUDIENCE)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plus(EXPIRY_DAYS, ChronoUnit.DAYS)))
            .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(creds.keyId())
            .type(com.nimbusds.jose.JOSEObjectType.JWT)
            .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new ECDSASigner(privateKey));
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign Apple client-secret JWT", e);
        }
        return jwt.serialize();
    }

    /**
     * Parses a PKCS8 PEM EC private key (the {@code .p8} contents). Tolerates
     * the {@code -----BEGIN/END PRIVATE KEY-----} armor and any surrounding
     * whitespace / newlines.
     */
    private static ECPrivateKey parsePrivateKey(String pem) {
        String base64 = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Apple private key is not valid base64", e);
        }
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            return (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse Apple EC private key", e);
        }
    }
}
