package com.jwt.security.server;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TokenExample {

  public static void main(String[] args)
      throws KeyStoreException,
             UnrecoverableKeyException,
             NoSuchAlgorithmException,
             IOException,
             InvalidKeySpecException {
    KeyStore keyStore = KeyStore.Builder.newInstance(
                                    new File("src/main/resources/keys/jwt-security-service-keystore.jks"),
                                    new KeyStore.PasswordProtection("123456".toCharArray()))
                                        .getKeyStore();
    Key privateKey = keyStore.getKey("jwt-security-service", "123456".toCharArray());

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

    try {
      Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) keyFactory.generatePublic(keySpec),
          (RSAPrivateKey) privateKey);
      String token = JWT.create()
                        .withIssuer("auth0")
                        .sign(algorithm);
      System.out.println(token);
      System.out.println("Generated token");
    } catch (JWTCreationException exception) {
      System.out.println(exception);
    }
  }
}
