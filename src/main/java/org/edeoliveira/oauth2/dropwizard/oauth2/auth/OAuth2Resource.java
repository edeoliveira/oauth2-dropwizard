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

import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import io.dropwizard.auth.AuthenticationException;
import org.apache.http.HttpStatus;
import org.edeoliveira.oauth2.dropwizard.OAuth2Config;
import org.edeoliveira.oauth2.dropwizard.oauth2.User;
import org.edeoliveira.oauth2.dropwizard.oauth2.apifest.AccessToken;
import org.edeoliveira.oauth2.dropwizard.oauth2.apifest.ApifestApiPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

/**
 * Oauth2 resource that handles :
 * /login: authenticates user and returns an auth cookie
 * /refresh: refresh authentication using the refresh token
 * /whoami: returns the user id
 * /logout: invalidates the authentication cookie
 *
 * @author Edouard De Oliveira
 */
@Path(value = "/oauth20")
@Produces(MediaType.APPLICATION_JSON)
public class OAuth2Resource {
    private static final Logger log = LoggerFactory.getLogger(OAuth2Resource.class);

    private Client client;
    private OAuth2Config cfg;
    private String tokenUrl;
    private CookieEncrypter engine;

    public OAuth2Resource(Client client, OAuth2Config cfg, CookieEncrypter engine) {
        this.client = client;
        this.cfg = cfg;
        this.tokenUrl = cfg.getUrl() + ApifestApiPath.TOKENS;
        this.engine = engine;
    }

    @POST
    @Timed
    @Path(value = "/login")
    public Response login(@FormParam("username") String username,
                          @FormParam("password") String password, @Context final HttpServletRequest request) {
        WebTarget target = client.target(tokenUrl);
        Invocation.Builder builder = target.request();

        Form form = new Form();
        form.param("grant_type", "password");
        form.param("username", username);
        form.param("password", password);
        form.param("scope", cfg.getScope());
        form.param("client_id", cfg.getClient_id());
        form.param("client_secret", cfg.getClient_secret());

        Response response = builder.accept(MediaType.APPLICATION_JSON)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED));

        if (response.getStatus() != HttpStatus.SC_OK) {
            response.close();
            return Response.
                    status(Response.Status.UNAUTHORIZED).entity("{ \"error\": \"auth failed\"}").build();
        }

        try {
            AccessToken token = response.readEntity(AccessToken.class);
            NewCookie nc = engine.buildCookie(username, token, request.getServerName());

            return Response.ok().cookie(nc).build();
        } catch (Exception ex) {
            log.error("Error while building login response", ex);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            response.close();
        }
    }

    @GET
    @Timed
    @Path(value = "/refresh")
    public Response refreshToken(@Auth User user,
                                 @Context final HttpServletRequest request) throws AuthenticationException {
        WebTarget target = client.target(tokenUrl);
        Invocation.Builder builder = target.request();

        Form form = new Form();
        form.param("grant_type", "refresh_token");
        form.param("refresh_token", user.getToken().getRefreshToken());
        form.param("client_id", cfg.getClient_id());
        form.param("client_secret", cfg.getClient_secret());

        Response response = builder.accept(MediaType.APPLICATION_JSON)
                .post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED));

        if (response.getStatus() == HttpStatus.SC_BAD_REQUEST) {
            log.debug("Error {} : invalid refresh token {}", user.getToken().getRefreshToken(), response.getStatus());
            response.close();
            throw new AuthenticationException("Invalid credentials");
        }

        try {
            AccessToken newToken = response.readEntity(AccessToken.class);
            NewCookie nc = engine.buildCookie(user.getName(), newToken, request.getServerName());

            return Response.ok().cookie(nc).build();
        } catch (Exception ex) {
            log.error("Error while building login response", ex);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            response.close();
        }
    }

    @GET
    @Timed
    @Path(value = "/whoami")
    public String whoAmI(@Auth User user, @Context final HttpServletRequest request) {
        return "{\"name\": \"" + user.getName() + "\"}";
    }

    @GET
    @Timed
    @Path(value = "/logout")
    public Response logout(@Context final HttpServletRequest request) {
        // invalidate cookie if exists
        ResponseBuilder reply = Response.ok();

        for (Cookie c : request.getCookies()) {
            if (OAuth2AuthFilter.AUTH_COOKIE_NAME.equals(c.getName())) {
                reply.cookie(new NewCookie(OAuth2AuthFilter.AUTH_COOKIE_NAME,
                        null, "/", request.getServerName(), null, 0, true));
                break;
            }
        }

        return reply.build();
    }
}
