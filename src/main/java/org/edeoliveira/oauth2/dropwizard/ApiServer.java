/*
 *  Copyright (C) 2015  oauth2-dropwizard project
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

package org.edeoliveira.oauth2.dropwizard;

import io.dropwizard.Application;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.CachingAuthenticator;
import io.dropwizard.jersey.setup.JerseyEnvironment;
import io.dropwizard.jetty.HttpsConnectorFactory;
import io.dropwizard.server.DefaultServerFactory;
import io.dropwizard.setup.Environment;
import org.edeoliveira.oauth2.dropwizard.health.OAuth2HealthCheck;
import org.edeoliveira.oauth2.dropwizard.oauth2.User;
import org.edeoliveira.oauth2.dropwizard.oauth2.auth.CookieEncrypter;
import org.edeoliveira.oauth2.dropwizard.oauth2.auth.OAuth2AuthFilter;
import org.edeoliveira.oauth2.dropwizard.oauth2.auth.OAuth2Authenticator;
import org.edeoliveira.oauth2.dropwizard.oauth2.auth.OAuth2Credentials;
import org.edeoliveira.oauth2.dropwizard.oauth2.auth.OAuth2Resource;
import org.edeoliveira.oauth2.dropwizard.oauth2.auth.RestClientBuilder;
import org.edeoliveira.oauth2.dropwizard.resources.HelloResource;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

import javax.ws.rs.client.Client;
import java.io.File;
import java.net.URI;
import java.net.URL;

/**
 * The main {@link Application}. Setup and starts this api server.
 *
 * @author Edouard De Oliveira
 */
public class ApiServer
        extends Application<ApiServerConfig> {

    public static void main(String[] args)
            throws Exception {
        if (args == null || args.length != 2) {
			URL url = ApiServer.class.getClassLoader().getResource("config.yml");
            if (url != null) {
                URI uri = url.toURI();
                if (!"jar".equals(uri.getScheme())) {
                    args = new String[]{"server", new File(uri).getAbsolutePath()};
                }
            }
        }

        new ApiServer().run(args);
    }

    @Override
    public String getName() {
        return "oauth2-dropwizard";
    }

    private void setupAuthentication(ApiServerConfig cfg, Environment env) throws Exception {
        final Client client = new RestClientBuilder(env, cfg).build(getName());

        // Health check for oauth2 server presence
        final OAuth2HealthCheck healthCheck = new OAuth2HealthCheck(cfg.getOauth2Config(), client);
        env.healthChecks().register("Oauth2 server", healthCheck);

        // Setting up the oauth2 authenticator
        boolean https = ((DefaultServerFactory)cfg.getServerFactory()).getApplicationConnectors().get(0) instanceof HttpsConnectorFactory;
        CookieEncrypter cookieEncrypter = new CookieEncrypter(cfg.getOauth2Config().getCookieSecretKey());
        cookieEncrypter.setSecureFlag(https);
        OAuth2Authenticator authenticator = new OAuth2Authenticator(cfg.getOauth2Config(), client);

        // Using cache authenticator
        CachingAuthenticator<OAuth2Credentials, User> cachingAuthenticator =
                new CachingAuthenticator<>(env.metrics(), authenticator, cfg.getCacheSpec());

        final OAuth2AuthFilter<User> oAuth2AuthFilter =
                new OAuth2AuthFilter.Builder<User, CachingAuthenticator<OAuth2Credentials, User>>()
                        .setAuthenticator(cachingAuthenticator)
                        .setCookieEncrypter(cookieEncrypter)
                        .build();

        JerseyEnvironment jerseyEnvironment = env.jersey();
        jerseyEnvironment.register(new AuthDynamicFeature(oAuth2AuthFilter));
        jerseyEnvironment.register(RolesAllowedDynamicFeature.class);
        jerseyEnvironment.register(new AuthValueFactoryProvider.Binder<>(User.class));

        // Register the oauth2 resource that handles client authentication
        jerseyEnvironment.register(new OAuth2Resource(client, cfg.getOauth2Config(), cookieEncrypter));
    }

    private void registerTestResources(ApiServerConfig cfg, Environment env) {
        // This is a test resource for demo purpose
        final HelloResource resource = new HelloResource(cfg.getTemplate(), cfg.getDefaultName());
        env.jersey().register(resource);
    }

    @Override
    public void run(ApiServerConfig cfg, Environment env)
            throws Exception {
        setupAuthentication(cfg, env);
        registerTestResources(cfg, env);
    }
}
