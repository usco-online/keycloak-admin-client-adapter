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

import java.io.StringReader;
import java.security.KeyPair;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;

import org.jose4j.jwt.consumer.JwtContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.smallrye.jwt.auth.principal.DefaultJWTTokenParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.build.Jwt;

@ApplicationScoped
public class KeycloakTokenService {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakTokenService.class);

  private KeycloakKeyConfiguration keyConfiguration;

  private KeyPair keyPair;

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
  }

  public VerificationLink encode(Token token) {
    try (Jsonb jsonb = JsonbBuilder.create()) {
      String payload = jsonb.toJson(token);
      String encodedPayload = encodeJwe(payload);
      return VerificationLink.fromValue(encodedPayload);
    } catch (Exception e) {
      LOG.error("problem during encode JWT: {}", e.getMessage(), e);
      throw new IllegalArgumentException("problem during encode" + e.getMessage(), e);
    }
  }

  public Token decode(VerificationLink link) {
    try (Jsonb jsonb = JsonbBuilder.create()) {
      String decodedPayload = decodeJwe(link.getValue());
      return jsonb.fromJson(decodedPayload, Token.class);
    } catch (Exception e) {
      LOG.error("problem during decode JWT: {}", e.getMessage(), e);
      throw new IllegalArgumentException("problem during decode" + e.getMessage(), e);
    }
  }

  private String encodeJwe(String payload) {
    try {
      LOG.debug("payload: {}", payload);
      JsonObject jsonObject = Json.createReader(new StringReader(payload)).readObject();
      String encodedPayload = Jwt.claims(jsonObject)
        .jwe()
        .header("cty", "JWE")
        .encrypt(keyPair.getPublic());
      LOG.debug("encoded payload: {}", encodedPayload);
      return encodedPayload;
    } catch (Exception e) {
      LOG.error("problem during encode JWT: {}", e.getMessage(), e);
      throw new IllegalArgumentException("problem during encode" + e.getMessage(), e);
    }
  }

  private String decodeJwe(String payload) {
    try {
      LOG.debug("payload: {}", payload);

      JWTAuthContextInfo info = new JWTAuthContextInfo();
      info.setPrivateDecryptionKey(keyPair.getPrivate());
      info.setExpGracePeriodSecs(30);

      DefaultJWTTokenParser parser = new DefaultJWTTokenParser();
      JwtContext jwtContext = parser.parse(payload, info);

      String decodedPayload = jwtContext.getJoseObjects().get(0).getPayload();
      LOG.debug("decoded payload: {}", decodedPayload);
      return decodedPayload;
    } catch (Exception e) {
      LOG.error("problem during decode JWT: {}", e.getMessage(), e);
      throw new IllegalArgumentException("problem during decode" + e.getMessage(), e);
    }
  }

}
