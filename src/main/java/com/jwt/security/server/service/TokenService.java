package com.jwt.security.server.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

public class TokenService {

  private final String KID = "jwt-security-service";
  private Algorithm algorithm;
  private int expirationTime = 60;

  @PostConstruct
  public void init() throws InvalidKeySpecException,
                            IOException,
                            NoSuchAlgorithmException,
                            UnrecoverableKeyException,
                            KeyStoreException {

    algorithm = Algorithm.RSA256(
        getPublicKey(),
        getPrivateKey());
  }

  public DecodedJWT verify(String token) {
    return JWT.require(algorithm)
              .withIssuer(KID)
              .acceptExpiresAt(expirationTime)
              .build()
              .verify(token);
  }

  public String generateToken(String username) {
    return JWT.create()
              .withIssuer(KID)
              .withKeyId(KID)
              .withSubject(username)
              .withExpiresAt(Instant.now().plusSeconds(expirationTime))
              .sign(algorithm);
  }

  private RSAPrivateKey getPrivateKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
    KeyStore keyStore = KeyStore.Builder.newInstance(
                                    new File("src/main/resources/keys/jwt-security-service-keystore.jks"),
                                    new KeyStore.PasswordProtection("123456".toCharArray()))
                                        .getKeyStore();
    return (RSAPrivateKey) keyStore.getKey("jwt-security-service", "123456".toCharArray());
  }

  private RSAPublicKey getPublicKey()
      throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
    String key =
        Files.readString(new File("src/main/resources/keys/jwt_security_service.pub").toPath(),
            Charset.defaultCharset());

    String publicKeyPEM = key
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replaceAll("\n", "")
        .replace("-----END PUBLIC KEY-----", "");

    byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
    return (RSAPublicKey) keyFactory.generatePublic(keySpec);
  }

}
