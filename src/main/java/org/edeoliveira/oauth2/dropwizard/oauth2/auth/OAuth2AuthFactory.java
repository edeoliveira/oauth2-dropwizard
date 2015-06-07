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

package org.edeoliveira.oauth2.dropwizard.oauth2.auth;

import com.google.common.base.Optional;
import io.dropwizard.auth.AuthFactory;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import org.edeoliveira.oauth2.dropwizard.oauth2.apifest.CookieToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

/**
 * A Dropwizard AuthFactory for OAuth2 HTTP authentication.
 *
 * @param <T> the principal type.
 * @author Edouard De Oliveira
 */
public final class OAuth2AuthFactory<T> extends AuthFactory<OAuth2Credentials, T> {
    protected final static String AUTH_COOKIE_NAME = "_dw_auth_cookie";
    private final static Logger log = LoggerFactory.getLogger(OAuth2AuthFactory.class);
    private final static String BEARER_TYPE = "Bearer";
    private final Class<T> generatedClass;
    private final CookieEncrypter engine;
    private final boolean required;
    private String prefix = BEARER_TYPE;

    @Context
    private HttpServletRequest request;

    public OAuth2AuthFactory(final boolean required,
                             final Authenticator<OAuth2Credentials, T> authenticator,
                             final CookieEncrypter engine,
                             final Class<T> generatedClass) {
        super(authenticator);
        this.engine = engine;
        this.required = required;
        this.generatedClass = generatedClass;
    }

    protected OAuth2AuthFactory<T> prefix(String prefix) {
        this.prefix = prefix;
        return this;
    }

    @Override
    @SuppressWarnings("unchecked")
    public AuthFactory<OAuth2Credentials, T> clone(boolean required) {
        return new OAuth2AuthFactory(required, authenticator(), this.engine, this.generatedClass).prefix(prefix);
    }

    @Override
    public Class<T> getGeneratedClass() {
        return generatedClass;
    }

    @Override
    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    public T provide() {
        if (request != null) {
            // This is where the credentials are extracted from the request
            Cookie cookie = null;

            for (Cookie c : request.getCookies()) {
                if (AUTH_COOKIE_NAME.equals(c.getName())) {
                    cookie = c;
                    break;
                }
            }

            try {
                if (cookie != null) {
                    // Extract username and token
                    CookieToken ct = engine.readCookie(cookie);
                    OAuth2Credentials creds = new OAuth2CookieCredentials(ct.getUsername(), ct.getToken());

                    final Optional<T> result = authenticator().authenticate(creds);
                    if (result.isPresent()) {
                        return result.get();
                    }
                } else {
                    String authString = request.getHeader(HttpHeaders.AUTHORIZATION);

                    if (authString != null && authString.startsWith(prefix)) {
                        String authToken = authString.substring(prefix.length());
                        OAuth2Credentials creds = new OAuth2HeaderCredentials(authToken);

                        final Optional<T> result = authenticator().authenticate(creds);
                        if (result.isPresent()) {
                            return result.get();
                        }
                    }
                }
            } catch (AuthenticationException e) {
                throw new WebApplicationException(Response.Status.UNAUTHORIZED);
            } catch (Exception ex) {
                log.error("Exception during cookie extraction", ex);
                throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
            }
        }

        if (required) {
            throw new WebApplicationException(Response.Status.UNAUTHORIZED);
        }

        return null;
    }
}