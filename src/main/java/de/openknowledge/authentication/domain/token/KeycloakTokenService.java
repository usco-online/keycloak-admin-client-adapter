/*
 * Copyright (C) open knowledge GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */
package de.openknowledge.authentication.domain.token;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.bind.JsonbBuilder;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.def.DefaultRsaKeyEncryptionJWEAlgorithmProvider;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.jose.jwe.JWEKeyStorage;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.AesCbcHmacShaEncryptionProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class KeycloakTokenService {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakTokenService.class);

  private KeycloakKeyConfiguration keyConfiguration;

  private KeyPair keyPair;

  private TokenSecret tokenSecret;

  @SuppressWarnings("unused")
  protected KeycloakTokenService() {
    // for framework
  }

  @Inject
  public KeycloakTokenService(KeycloakKeyConfiguration aKeyConfiguration) {
    keyConfiguration = aKeyConfiguration;
  }

  @PostConstruct
  public void init() {
    LOG.debug("check configuration");
    keyConfiguration.validate();
    keyPair = KeycloakKeyService.readKeyPair(keyConfiguration);
    tokenSecret = TokenSecret.fromValue(keyConfiguration.getTokenSecret());
    CryptoIntegration.init(this.getClass().getClassLoader());
  }

  public VerificationLink encode(Token token) {
    try {
      String payload = JsonbBuilder.create().toJson(token);
      LOG.debug("payload: {}", payload);
      JWE jwe = jwtEncode(tokenSecret, keyPair.getPublic());
      jwe.content(payload.getBytes(StandardCharsets.UTF_8));
      String encodedPayload = jwe.encodeJwe(getAlgorithmProvider(), getEncryptionProvider());
      LOG.debug("encoded payload: {}", encodedPayload);
      return VerificationLink.fromValue(encodedPayload);
    } catch (JWEException e) {
      LOG.error("problem during encode JWT: {}", e.getMessage(), e);
      throw new IllegalArgumentException("problem during encode" + e.getMessage(), e);
    }
  }

  public Token decode(VerificationLink link) {
    try {
      LOG.debug("payload: {}", link.getValue());
      JWE jwe = jwtDecoder(tokenSecret, keyPair.getPrivate());
      jwe.verifyAndDecodeJwe(link.getValue(), getAlgorithmProvider(), getEncryptionProvider());
      String decodedPayload = new String(jwe.getContent(), StandardCharsets.UTF_8);
      LOG.debug("decoded payload: {}", decodedPayload);
      return JsonbBuilder.create().fromJson(decodedPayload, Token.class);
    } catch (JWEException e) {
      LOG.error("problem during decode JWT: {}", e.getMessage(), e);
      throw new IllegalArgumentException("problem during decode" + e.getMessage(), e);
    }
  }

  private JWE jwtEncode(TokenSecret tokenSecret, PublicKey encryptionKey) {
    JWEHeader jweHeader = new JWEHeader(JWEConstants.A256CBC_HS512, JWEConstants.A256CBC_HS512, null);
    JWE jwe = new JWE();
    jwe.header(jweHeader);
    jwe.getKeyStorage().setEncryptionKey(encryptionKey);
    enrichKeyStorage(jwe, tokenSecret);
    return jwe;
  }

  private JWE jwtDecoder(TokenSecret tokenSecret, PrivateKey decryptionKey) {
    JWE jwe = new JWE();
    jwe.getKeyStorage().setDecryptionKey(decryptionKey);
    enrichKeyStorage(jwe, tokenSecret);
    return jwe;
  }

  private void enrichKeyStorage(JWE jwe, TokenSecret tokenSecret) {
    SecretKey aesKey = new SecretKeySpec(tokenSecret.asByteArray(), "AES");
    SecretKey hmacKey = new SecretKeySpec(tokenSecret.asByteArray(), "HMACSHA2");
    jwe.getKeyStorage().setCEKKey(aesKey, JWEKeyStorage.KeyUse.ENCRYPTION);
    jwe.getKeyStorage().setCEKKey(hmacKey, JWEKeyStorage.KeyUse.SIGNATURE);
  }

  private JWEAlgorithmProvider getAlgorithmProvider() {
    return new DefaultRsaKeyEncryptionJWEAlgorithmProvider("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
  }

  private JWEEncryptionProvider getEncryptionProvider() {
    return new AesCbcHmacShaEncryptionProvider.Aes256CbcHmacSha512Provider();
  }

}
