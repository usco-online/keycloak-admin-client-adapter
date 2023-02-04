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
package de.openknowledge.authentication.domain;

import java.lang.reflect.InvocationTargetException;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.client.ClientBuilder;

import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.keycloak.admin.client.ClientBuilderWrapper;
import org.keycloak.admin.client.JacksonProvider;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RealmsResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.admin.client.token.TokenService;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class KeycloakAdapter {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakAdapter.class);

  private Keycloak keycloak;

  private TokenService tokenService;

  protected KeycloakAdapter() {
    // for framework
  }

  @Inject
  public KeycloakAdapter(KeycloakAdapterConfiguration adapterConfig) {
    ClientBuilder clientBuilder = ClientBuilderWrapper.create(null, false);
    clientBuilder.register(JacksonProvider.class, 100);
    try {
      clientBuilder.getClass().getMethod("connectionPoolSize", int.class)
        .invoke(clientBuilder, adapterConfig.getConnectionPoolSize());
    } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
      LOG.error("Cannot set connectionPoolSize", e);
    }

    keycloak = KeycloakBuilder.builder()
        .serverUrl(adapterConfig.getServerUrl())
        .realm(adapterConfig.getMasterRealm())
        .grantType(adapterConfig.getGrantType())
        .username(adapterConfig.getUsername())
        .password(adapterConfig.getPassword())
        .clientId(adapterConfig.getClientId())
        .resteasyClient(clientBuilder.build())
        .build();
    tokenService = ((ResteasyClient)clientBuilder.build()).target(adapterConfig.getServerUrl()).proxy(TokenService.class);
  }

  public List<RealmRepresentation> findAll() {
    RealmsResource realmsResource = keycloak.realms();
    return realmsResource.findAll();
  }

  public RealmResource findRealmResource(RealmName realmName) {
    return keycloak.realm(realmName.getValue());
  }

  public ClientsResource findClientsResource(RealmName realmName) {
    return findRealmResource(realmName).clients();
  }

  public ClientResource findClientResource(RealmName realmName, ClientId clientId) {
    ClientsResource clientsResource = findClientsResource(realmName);
    String clientUuid = findClientUuid(clientsResource, clientId);
    return clientsResource.get(clientUuid);
  }

  public UsersResource findUsersResource(RealmName realmName) {
    RealmResource realmResource = findRealmResource(realmName);
    return realmResource.users();
  }

  public GroupsResource findGroupsResource(RealmName realmName) {
    RealmResource realmResource = findRealmResource(realmName);
    return realmResource.groups();
  }

  public RolesResource findRealmRolesResource(RealmName realmName) {
    RealmResource realmResource = findRealmResource(realmName);
    return realmResource.roles();
  }

  public RolesResource findClientRolesResource(RealmName realmName, ClientId clientId) {
    ClientResource clientResource = findClientResource(realmName, clientId);
    return clientResource.roles();
  }

  public String findClientUuid(RealmName realmName, ClientId clientId) {
    ClientsResource clientsResource = findClientsResource(realmName);
    return findClientUuid(clientsResource, clientId);
  }

  public String findClientUuid(ClientsResource clientsResource, ClientId clientId) {
    List<ClientRepresentation> clientRepresentations = clientsResource.findByClientId(clientId.getValue());
    if (clientRepresentations.isEmpty()) {
      throw new NotFoundException("client not found for clientId '" + clientId + "'");
    }
    return clientRepresentations.stream().findFirst().get().getId();
  }

  public TokenService getTokenService() {
    return tokenService;
  }
}
