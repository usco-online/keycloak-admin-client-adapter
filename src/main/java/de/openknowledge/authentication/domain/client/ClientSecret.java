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
package de.openknowledge.authentication.domain.client;

import static org.apache.commons.lang3.Validate.notBlank;

import de.openknowledge.common.domain.AbstractStringValueObject;

public class ClientSecret extends AbstractStringValueObject {

  private ClientSecret(String value) {
    super(value);
  }

  protected ClientSecret() {
    super();
    // for framework
  }

  public static ClientSecret fromValue(String clientSecret) {
    notBlank(clientSecret, "clientSecret must not be blank");
    return new ClientSecret(clientSecret);
  }

  @Override
  public String toString() {
    return "******";
  }

}
