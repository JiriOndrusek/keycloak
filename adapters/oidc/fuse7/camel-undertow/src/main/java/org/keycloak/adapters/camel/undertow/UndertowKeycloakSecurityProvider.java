/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.adapters.camel.undertow;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.Credential;
import io.undertow.security.idm.IdentityManager;
import io.undertow.security.impl.SecurityContextImpl;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.session.InMemorySessionManager;
import io.undertow.server.session.SessionManager;
import io.undertow.util.AttachmentKey;
import io.undertow.util.StatusCodes;
import org.apache.camel.component.undertow.UndertowConsumer;
import org.apache.camel.component.undertow.spi.UndertowSecurityProvider;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.*;
import org.keycloak.adapters.spi.*;
import org.keycloak.adapters.undertow.*;
import org.keycloak.enums.TokenStore;
import org.keycloak.representations.adapters.config.AdapterConfig;

/**
 *
 * @author hmlnarik
 */
public class UndertowKeycloakSecurityProvider implements UndertowSecurityProvider {
    private static final Logger LOG = Logger.getLogger(UndertowKeycloakSecurityProvider.class.getName());

    public static final AttachmentKey<KeycloakPrincipal> KEYCLOAK_PRINCIPAL_KEY = AttachmentKey.create(KeycloakPrincipal.class);

    private static final IdentityManager IDENTITY_MANAGER = new IdentityManager() {
        @Override
        public Account verify(Account account) {
            return account;
        }

        @Override
        public Account verify(String id, Credential credential) {
            throw new IllegalStateException("Should never be called in Keycloak flow");
        }

        @Override
        public Account verify(Credential credential) {
            throw new IllegalStateException("Should never be called in Keycloak flow");
        }
    };


    private AdapterDeploymentContext deploymentContext;

    private SessionManager sessionManager;

    private UndertowKeycloakSecurityConfiguration configuration;

    private AdapterConfig adapterConfig;

    private final UndertowUserSessionManagement userSessionManagement = new UndertowUserSessionManagement();

    public UndertowKeycloakSecurityProvider() {
    }

    @Override
    public void addHeader(BiConsumer<String, Object> consumer, HttpServerExchange httpExchange) {
        KeycloakPrincipal principal = httpExchange.getAttachment(KEYCLOAK_PRINCIPAL_KEY);
        LOG.log(Level.FINE, "principal: {0}", principal);
        if (principal != null) {
            consumer.accept(KeycloakPrincipal.class.getName(), principal);
        }
    }


    @Override
    public int authenticate(HttpServerExchange httpExchange, List<String> allowedRoles) throws Exception {
        if (shouldSkip(httpExchange.getRequestPath())) {
            return StatusCodes.OK;
        }

        OIDCUndertowHttpFacade facade = new OIDCUndertowHttpFacade(httpExchange);
        KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);

        if (deployment == null || !deployment.isConfigured()) {
            httpExchange.setStatusCode(StatusCodes.FORBIDDEN);
            LOG.fine("deployment not configured");
            return StatusCodes.FORBIDDEN;
        }

        LOG.fine("executing PreAuthActionsHandler");
        SessionManagementBridge bridge = new SessionManagementBridge(userSessionManagement, sessionManager);
        PreAuthActionsHandler preAuth = new PreAuthActionsHandler(bridge, deploymentContext, facade);
        if (preAuth.handleRequest()) return StatusCodes.OK;

        SecurityContext securityContext = httpExchange.getSecurityContext();
        if (securityContext == null) {
            securityContext = new SecurityContextImpl(httpExchange, IDENTITY_MANAGER);
        }
        AdapterTokenStore tokenStore = getTokenStore(httpExchange, facade, deployment, securityContext);
        tokenStore.checkCurrentToken();

        LOG.fine("executing AuthenticatedActionsHandler");
        RequestAuthenticator authenticator = new UndertowRequestAuthenticator(facade, deployment, this.configuration.getConfidentialPort(), securityContext, httpExchange, tokenStore);
        AuthOutcome outcome = authenticator.authenticate();

        if (outcome == AuthOutcome.AUTHENTICATED) {
            LOG.fine("AUTHENTICATED");
            if (httpExchange.isResponseComplete()) {
                return StatusCodes.OK;
            }
            AuthenticatedActionsHandler actions = new AuthenticatedActionsHandler(deployment, facade);
            if (actions.handledRequest()) {
                return StatusCodes.OK;
            } else {
                final Account authenticatedAccount = securityContext.getAuthenticatedAccount();
                if (authenticatedAccount instanceof KeycloakUndertowAccount) {
                    final KeycloakUndertowAccount kua = (KeycloakUndertowAccount) authenticatedAccount;
                    httpExchange.putAttachment(KEYCLOAK_PRINCIPAL_KEY, (KeycloakPrincipal) kua.getPrincipal());
                }

                Set<String> roles = Optional
                        .ofNullable(authenticatedAccount.getRoles())
                        .orElse((Set<String>) Collections.EMPTY_SET);

                LOG.log(Level.FINE, "Allowed roles: {0}, current roles: {1}", new Object[] {allowedRoles, roles});

                if (isRoleAllowed(roles, allowedRoles)) {
                    return StatusCodes.OK;
                } else {
                    return StatusCodes.FORBIDDEN;
                }


            }
        }

        AuthChallenge challenge = authenticator.getChallenge();
        if (challenge != null) {
            LOG.fine("challenge");
            challenge.challenge(facade);
            return challenge.getResponseCode();
        }

        return StatusCodes.FORBIDDEN;
    }

    @Override
    public boolean acceptConfiguration(Object configuration, String endpointUri) throws Exception {
        if(configuration instanceof UndertowKeycloakSecurityConfiguration) {
            this.configuration = (UndertowKeycloakSecurityConfiguration)configuration;
            this.sessionManager = new InMemorySessionManager(endpointUri);
            this.deploymentContext = getDeploymentContext();
            return true;
        }

        return false;
    }

    public boolean isRoleAllowed(Set<String> roles, List<String> allowedRoles) throws Exception {
        for (String role : allowedRoles) {
            if (roles.contains(role)) {
                return true;
            }
        }

        return false;
    }

    protected AdapterTokenStore getTokenStore(HttpServerExchange exchange, HttpFacade facade, KeycloakDeployment deployment, SecurityContext securityContext) {
        if (deployment.getTokenStore() == TokenStore.SESSION) {
            return new UndertowSessionTokenStore(exchange, deployment, userSessionManagement, securityContext);
        } else {
            return new UndertowCookieTokenStore(facade, deployment, securityContext);
        }
    }

    private boolean shouldSkip(String requestPath) {
        //todo cache pattern
        return this.configuration.getSkipPattern() != null && getSkipPatternAsPattern().matcher(requestPath).matches();
    }

    private AdapterDeploymentContext getDeploymentContext() {
        if (this.configuration != null) {
            LOG.log(Level.INFO, "Using {0} to resolve Keycloak configuration on a per-request basis.", this.configuration.getClass());
            return new AdapterDeploymentContext(this.configuration);
        } else if (adapterConfig != null) {
            KeycloakDeployment kd = KeycloakDeploymentBuilder.build(adapterConfig);
            return new AdapterDeploymentContext(kd);
        }

        LOG.warning("Adapter is unconfigured, Keycloak will deny every request");
        return new AdapterDeploymentContext();
    }

    private Pattern getSkipPatternAsPattern() {
        return this.configuration.getSkipPattern() == null
                ? null
                : Pattern.compile(this.configuration.getSkipPattern(), Pattern.DOTALL);
    }

    public List<String> computeAllowedRoles(List<String> allowedRoles) {
        List<String> res = allowedRoles == null ? Collections.<String>emptyList() : allowedRoles;
        if (res.isEmpty()) {
            LOG.warning("No roles were configured, Keycloak will deny every request");
        }
        LOG.log(Level.FINE, "Allowed roles: {0}", res);
        return res;
    }


    public AdapterConfig getAdapterConfig() {
        return adapterConfig;
    }

    public void setAdapterConfig(AdapterConfig adapterConfig) {
        this.adapterConfig = adapterConfig;
    }
}
