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
package de.openknowledge.authentication.domain.registration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import static de.openknowledge.common.domain.ObjectMother.CLIENT_ID;
import static de.openknowledge.common.domain.ObjectMother.ISSUER;
import static de.openknowledge.common.domain.ObjectMother.REALM_NAME;
import static de.openknowledge.common.domain.ObjectMother.USERNAME;
import static de.openknowledge.common.domain.ObjectMother.USER_IDENTIFIER;
import static de.openknowledge.common.domain.ObjectMother.VERIFICATION_LINK;
import static de.openknowledge.common.domain.ObjectMother.createToken;
import static de.openknowledge.common.domain.ObjectMother.createUserAccount;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import de.openknowledge.authentication.domain.KeycloakServiceConfiguration;
import de.openknowledge.authentication.domain.role.RoleName;
import de.openknowledge.authentication.domain.role.RoleType;
import de.openknowledge.authentication.domain.token.KeycloakTokenService;
import de.openknowledge.authentication.domain.token.Token;
import de.openknowledge.authentication.domain.user.EmailVerifiedMode;
import de.openknowledge.authentication.domain.user.KeycloakUserService;
import de.openknowledge.authentication.domain.user.UserAccount;
import de.openknowledge.authentication.domain.user.UserCreationFailedException;
import de.openknowledge.authentication.domain.user.UserIdentifier;

@ExtendWith(MockitoExtension.class)
public class KeycloakRegistrationServiceTest {

  @Mock
  private KeycloakUserService keycloakUserService;

  @Mock
  private KeycloakTokenService keycloakTokenService;

  private KeycloakRegistrationService service;

  private UserAccount account;

  private Token token;

  @BeforeEach
  void setup() {
    account = createUserAccount(Boolean.TRUE);
    token = createToken();
    KeycloakServiceConfiguration serviceConfiguration = new KeycloakServiceConfiguration(REALM_NAME.getValue(), CLIENT_ID.getValue());
    KeycloakRegistrationServiceConfiguration registrationServiceConfiguration = new KeycloakRegistrationServiceConfiguration(
        RegistrationMode.DOUBLE_OPT_IN.name(), RegistrationRequirement.ROLE.name(), "5", "MINUTES");
    service = new KeycloakRegistrationService(serviceConfiguration,
        registrationServiceConfiguration,
        keycloakUserService,
        keycloakTokenService);
    service.init();
  }

  @Test
  void returnValidOnCreateUser() {
    // checkUserExists
    doReturn(Boolean.FALSE).when(keycloakUserService).checkAlreadyExist(account);
    // createUser
    doReturn(account).when(keycloakUserService).createUser(account, EmailVerifiedMode.REQUIRED);
    // joinRoles
    doNothing().when(keycloakUserService).joinRoles(USER_IDENTIFIER, RoleType.REALM, RoleName.fromValue(CLIENT_ID.getValue()));
    UserAccount response = service.register(account);
    assertThat(response.getIdentifier()).isEqualTo(USER_IDENTIFIER);
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }

  @Test
  void returnValidOnCreateUserWithoutDoubleOptIn() {
    // setup service
    KeycloakServiceConfiguration serviceConfiguration = new KeycloakServiceConfiguration(REALM_NAME.getValue(), CLIENT_ID.getValue());
    KeycloakRegistrationServiceConfiguration registrationServiceConfiguration = new KeycloakRegistrationServiceConfiguration(
        RegistrationMode.DEFAULT.name(), RegistrationRequirement.ROLE.name(), "5", "MINUTES");
    KeycloakRegistrationService noDoubleOptInService = new KeycloakRegistrationService(serviceConfiguration,
        registrationServiceConfiguration,
        keycloakUserService,
        keycloakTokenService);
    // setup response data
    UserAccount account = createUserAccount(Boolean.TRUE, Boolean.TRUE);
    // checkUserExists
    doReturn(Boolean.FALSE).when(keycloakUserService).checkAlreadyExist(account);
    // createUser
    doReturn(account).when(keycloakUserService).createUser(account, EmailVerifiedMode.DEFAULT);
    // joinRoles
    doNothing().when(keycloakUserService).joinRoles(USER_IDENTIFIER, RoleType.REALM, RoleName.fromValue(CLIENT_ID.getValue()));
    // run test
    UserAccount response = noDoubleOptInService.register(account);
    assertThat(response.getIdentifier()).isEqualTo(USER_IDENTIFIER);
    assertThat(response.getEmailVerified()).isTrue();
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }

  @Test
  void returnValidOnCreateUserWithoutRoleRequired() {
    // setup service
    KeycloakServiceConfiguration serviceConfiguration = new KeycloakServiceConfiguration(REALM_NAME.getValue(), CLIENT_ID.getValue());
    KeycloakRegistrationServiceConfiguration registrationServiceConfiguration = new KeycloakRegistrationServiceConfiguration(
        RegistrationMode.DOUBLE_OPT_IN.name(), RegistrationRequirement.DEFAULT.name(), "5", "MINUTES");
    KeycloakRegistrationService noRoleRequiredService = new KeycloakRegistrationService(serviceConfiguration,
        registrationServiceConfiguration,
        keycloakUserService,
        keycloakTokenService);
    // checkUserExists
    doReturn(Boolean.FALSE).when(keycloakUserService).checkAlreadyExist(account);
    // createUser
    doReturn(account).when(keycloakUserService).createUser(account, EmailVerifiedMode.REQUIRED);
    // run test
    UserAccount response = noRoleRequiredService.register(account);
    assertThat(response.getIdentifier()).isEqualTo(USER_IDENTIFIER);
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }

  @Test()
  void returnAlreadyExistsOnCreateUser() {
    // checkUserExists
    doReturn(Boolean.TRUE).when(keycloakUserService).checkAlreadyExist(account);
    // run test
    assertThrows(RegistrationFailedException.class, () -> {
      service.register(account);
    });
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }

  @Test
  void returnInvalidOnCreateUser() {
    // checkUserExists
    doReturn(Boolean.FALSE).when(keycloakUserService).checkAlreadyExist(account);
    // createUser
    UserCreationFailedException exception = new UserCreationFailedException(USERNAME.getValue(), 409, "User already exists");
    doThrow(exception).when(keycloakUserService).createUser(account, EmailVerifiedMode.REQUIRED);
    // run test
    assertThrows(RegistrationFailedException.class, () -> {
      service.register(account);
    });
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }

  @Test
  void verifyEmailAddress() {
    // decode token
    doReturn(token).when(keycloakTokenService).decode(VERIFICATION_LINK);
    // update mail verification
    doNothing().when(keycloakUserService).updateMailVerification(USER_IDENTIFIER);
    // run test
    UserIdentifier userIdentifier = service.verifyEmailAddress(VERIFICATION_LINK, ISSUER);
    assertThat(userIdentifier).isEqualTo(USER_IDENTIFIER);
    verifyNoMoreInteractions(keycloakUserService, keycloakTokenService);
  }


}
