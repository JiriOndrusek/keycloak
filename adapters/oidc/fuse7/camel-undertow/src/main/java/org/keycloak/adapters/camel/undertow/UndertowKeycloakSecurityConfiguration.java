package org.keycloak.adapters.camel.undertow;

import org.keycloak.adapters.KeycloakConfigResolver;

public interface UndertowKeycloakSecurityConfiguration extends KeycloakConfigResolver {

    default int getConfidentialPort() {
        return 8443;
    }

    default String getSkipPattern() {
        return null;
    }
}
