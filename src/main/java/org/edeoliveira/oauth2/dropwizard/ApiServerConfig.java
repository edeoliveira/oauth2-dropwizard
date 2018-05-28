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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.cache.CacheBuilderSpec;
import io.dropwizard.Configuration;
import io.dropwizard.client.JerseyClientConfiguration;
import io.dropwizard.jetty.ConnectorFactory;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.NotNull;

/**
 * YML configuration is mapped to this class to configure the server.
 *
 * @author Edouard De Oliveira
 */
public class ApiServerConfig
        extends Configuration {
    @JsonProperty
    private CacheBuilderSpec cacheSpec;

    @NotEmpty
    @JsonProperty
    private String template;

    @NotEmpty
    @JsonProperty
    private String defaultName;

    @NotNull
    @JsonProperty
    private JerseyClientConfiguration httpClient = new JerseyClientConfiguration();

    @JsonProperty("clientConfig")
    private ConnectorFactory clientConfig;

    @NotNull
    @JsonProperty
    private OAuth2Config oauth2Config;

    public JerseyClientConfiguration getJerseyClientConfiguration() {
        return httpClient;
    }

    public String getTemplate() {
        return template;
    }

    public String getDefaultName() {
        return defaultName;
    }

    public CacheBuilderSpec getCacheSpec() {
        return cacheSpec;
    }

    public OAuth2Config getOauth2Config() {
        return oauth2Config;
    }

    public ConnectorFactory getClientConfig() {
        return clientConfig;
    }
}
