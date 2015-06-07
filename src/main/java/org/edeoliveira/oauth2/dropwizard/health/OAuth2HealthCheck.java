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

package org.edeoliveira.oauth2.dropwizard.health;

import com.codahale.metrics.health.HealthCheck;
import org.apache.http.HttpStatus;
import org.edeoliveira.oauth2.dropwizard.OAuth2Config;
import org.edeoliveira.oauth2.dropwizard.oauth2.apifest.ApifestApiPath;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * A {@link HealthCheck} to check if OAuth2 server is running
 *
 * @author Edouard De Oliveira
 */
public class OAuth2HealthCheck extends HealthCheck {

    private Client client;
    private String validationUrl;

    public OAuth2HealthCheck(OAuth2Config cfg, Client client) {
        this.client = client;
        this.validationUrl = cfg.getUrl() + ApifestApiPath.TOKENS_VALIDATION;
    }

    @Override
    protected Result check() throws Exception {
        WebTarget target = client.target(validationUrl);
        Response response = null;
        try {
            response = target.request().accept(MediaType.APPLICATION_JSON).get();

            if (response.getStatus() != HttpStatus.SC_BAD_REQUEST)
                return Result.unhealthy("OAuth2 server bad response (err code: " + response.getStatus() + ")");
        } catch (Exception ex) {
            return Result.unhealthy("OAuth2 server is unreachable");
        } finally {
            if (response != null)
                response.close();
        }

        return Result.healthy();
    }
}