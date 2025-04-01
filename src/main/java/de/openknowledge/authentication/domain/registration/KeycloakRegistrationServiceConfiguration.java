package de.openknowledge.authentication.domain.registration;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class KeycloakRegistrationServiceConfiguration {

  private static final String MODE_PROPERTY = "keycloak.registration.mode";
  private static final String ROLE_REQUIRED_PROPERTY = "keycloak.registration.roleRequire";
  private static final String TOKEN_LIFE_TIME_PROPERTY = "keycloak.registration.tokenLifeTime";
  private static final String TOKEN_TIME_UNIT_PROPERTY = "keycloak.registration.tokenTimeUnit";
  private static final String PASSWORD_RESET_LIFE_TIME_PROPERTY = "keycloak.registration.passwordResetLifeTime";
  private static final String PASSWORD_RESET_TIME_UNIT_PROPERTY = "keycloak.registration.passwordResetTimeUnit";

  private static final String MODE_DEFAULT = "DEFAULT";
  private static final String ROLE_REQUIRED_DEFAULT = "DEFAULT";
  private static final String TOKEN_LIFE_TIME_DEFAULT = "5";
  private static final String TOKEN_TIME_UNIT_DEFAULT = "MINUTES";
  private static final String PASSWORD_RESET_LIFE_TIME_DEFAULT = "1";
  private static final String PASSWORD_RESET_TIME_UNIT_DEFAULT = "DAYS";

  private String registrationMode;

  private String registrationRequirement;

  private String tokenLifeTime;

  private String timeUnit;

  private String passwordResetLifeTime;

  private String passwordResetTimeUnit;

  protected KeycloakRegistrationServiceConfiguration() {
    // for framework
  }

  @Inject
  public KeycloakRegistrationServiceConfiguration(
      @ConfigProperty(name = MODE_PROPERTY, defaultValue = MODE_DEFAULT) String aRegistrationMode,
      @ConfigProperty(name = ROLE_REQUIRED_PROPERTY, defaultValue = ROLE_REQUIRED_DEFAULT) String aRegistrationRequirement,
      @ConfigProperty(name = TOKEN_LIFE_TIME_PROPERTY, defaultValue = TOKEN_LIFE_TIME_DEFAULT) String aTokenLifeTime,
      @ConfigProperty(name = TOKEN_TIME_UNIT_PROPERTY, defaultValue = TOKEN_TIME_UNIT_DEFAULT) String aTimeUnit,
      @ConfigProperty(name = PASSWORD_RESET_LIFE_TIME_PROPERTY, defaultValue = PASSWORD_RESET_LIFE_TIME_DEFAULT) String aPasswordResetLifeTime,
      @ConfigProperty(name = PASSWORD_RESET_TIME_UNIT_PROPERTY, defaultValue = PASSWORD_RESET_TIME_UNIT_DEFAULT) String aPasswordResetTimeUnit) {
    registrationMode = aRegistrationMode;
    registrationRequirement = aRegistrationRequirement;
    tokenLifeTime = aTokenLifeTime;
    timeUnit = aTimeUnit;
    passwordResetLifeTime = aPasswordResetLifeTime;
    passwordResetTimeUnit = aPasswordResetTimeUnit;
  }

  public String getRegistrationMode() {
    return registrationMode;
  }

  public String getRegistrationRequirement() {
    return registrationRequirement;
  }

  public String getTokenLifeTime() {
    return tokenLifeTime;
  }

  public String getTimeUnit() {
    return timeUnit;
  }

  public String getPasswordResetLifeTime() {
    return passwordResetLifeTime;
  }

  public String getPasswordResetTimeUnit() {
    return passwordResetTimeUnit;
  }

  void validate() {
    // not needed, all values as defaults
  }

}
