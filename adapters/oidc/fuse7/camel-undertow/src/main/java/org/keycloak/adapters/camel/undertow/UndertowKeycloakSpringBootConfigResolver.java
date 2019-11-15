package org.keycloak.adapters.camel.undertow;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootProperties;

public class UndertowKeycloakSpringBootConfigResolver extends KeycloakSpringBootConfigResolver  {
    private final KeycloakDeployment keycloakDeployment;

    public UndertowKeycloakSpringBootConfigResolver(KeycloakSpringBootProperties properties) {
        keycloakDeployment = KeycloakDeploymentBuilder.build(properties);
    }

    @Override
    public KeycloakDeployment resolve(OIDCHttpFacade.Request request) {
        return keycloakDeployment;
    }

}
