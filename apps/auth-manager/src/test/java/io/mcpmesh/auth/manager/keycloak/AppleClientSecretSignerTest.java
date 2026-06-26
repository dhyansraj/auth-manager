package io.mcpmesh.auth.manager.keycloak;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit test for {@link AppleClientSecretSigner}. Generates a throwaway P-256 EC
 * key, mints the Apple client-secret JWT, and verifies it parses with the
 * expected iss/sub/aud, alg=ES256, and a valid signature.
 */
class AppleClientSecretSignerTest {

    private static KeyPair keyPair;
    private static String privateKeyPem;

    @BeforeAll
    static void genKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = gen.generateKeyPair();
        // PKCS8 PEM armor, mirroring the .p8 download Apple gives operators.
        String b64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }

    @Test
    void mint_producesValidEs256Jwt() throws Exception {
        var creds = new PlatformOAuthProperties.AppleProvider(
            "io.mcpmesh.app.service", "TEAM123456", "KEY7890AB", privateKeyPem);

        String token = new AppleClientSecretSigner().mint(creds);

        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("KEY7890AB");

        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("TEAM123456");
        assertThat(claims.getSubject()).isEqualTo("io.mcpmesh.app.service");
        assertThat(claims.getAudience()).containsExactly("https://appleid.apple.com");
        assertThat(claims.getIssueTime()).isNotNull();
        assertThat(claims.getExpirationTime()).isAfter(new Date());

        boolean verified = jwt.verify(new ECDSAVerifier((ECPublicKey) keyPair.getPublic()));
        assertThat(verified).isTrue();
    }

    @Test
    void mint_handlesPrivateKeyWithoutPemArmor() throws Exception {
        String raw = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        var creds = new PlatformOAuthProperties.AppleProvider(
            "svc", "TEAM", "KID", raw);

        String token = new AppleClientSecretSigner().mint(creds);

        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.verify(new ECDSAVerifier((ECPublicKey) keyPair.getPublic()))).isTrue();
    }

    @Test
    void mint_rejectsUnconfiguredCreds() {
        var creds = new PlatformOAuthProperties.AppleProvider(null, null, null, null);
        org.junit.jupiter.api.Assertions.assertThrows(
            IllegalStateException.class, () -> new AppleClientSecretSigner().mint(creds));
    }

    @Test
    void parsedPrivateKeyIsEcPrivateKey() {
        assertThat(keyPair.getPrivate()).isInstanceOf(ECPrivateKey.class);
    }
}
