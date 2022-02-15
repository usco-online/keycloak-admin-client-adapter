package de.openknowledge.authentication.domain.client;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.openknowledge.authentication.domain.ClientId;
import de.openknowledge.authentication.domain.KeycloakAdapter;
import de.openknowledge.authentication.domain.KeycloakServiceConfiguration;
import de.openknowledge.authentication.domain.RealmName;

@ApplicationScoped
public class KeycloakClientService {

  private static final Logger LOG = LoggerFactory.getLogger(KeycloakClientService.class);

  private KeycloakAdapter keycloakAdapter;

  private RealmName realm;

  protected KeycloakClientService() {
    // for framework
  }

  @Inject
  public KeycloakClientService(KeycloakServiceConfiguration theKeycloakServiceConfiguration,
                               KeycloakAdapter theKeycloakAdapter) {
    keycloakAdapter = theKeycloakAdapter;
    realm = theKeycloakServiceConfiguration.getRealm();
  }

  public ClientSecret getClientSecret(ClientId clientId) {
    ClientResource clientResource = keycloakAdapter.findClientResource(realm, clientId);
    CredentialRepresentation clientSecret = clientResource.getSecret();
    return ClientSecret.fromValue(clientSecret.getValue());
  }

}
