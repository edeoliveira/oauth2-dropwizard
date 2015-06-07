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

package org.edeoliveira.oauth2.dropwizard.oauth2.apifest;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.io.Serializable;

/**
 * Holds the data which is returned by the oauth2 server when requesting a token.
 *
 * @author Edouard De Oliveira
 */
@JsonPropertyOrder({"access_token", "refresh_token", "token_type", "expires_in", "refresh_expires_in"})
public class AccessToken implements Serializable {

    private static final long serialVersionUID = -8686542993964102501L;

    @JsonProperty("access_token")
    private String token = "";

    @JsonProperty("refresh_token")
    private String refreshToken = "";

    @JsonProperty("expires_in")
    private String expiresIn = "";

    @JsonProperty("refresh_expires_in")
    private String refreshExpiresIn = "";

    // bearer or mac
    @JsonProperty("token_type")
    private String type = "";

    @JsonProperty("scope")
    private String scope = "";

    public AccessToken() {
    }

    public String getToken() {
        return token;
    }

    public void setToken(String accessToken) {
        this.token = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(String expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getRefreshExpiresIn() {
        return refreshExpiresIn;
    }

    public void setRefreshExpiresIn(String refreshExpiresIn) {
        this.refreshExpiresIn = refreshExpiresIn;
    }

    public String getType() {
        return type;
    }

    public void setType(String tokenType) {
        this.type = tokenType;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((expiresIn == null) ? 0 : expiresIn.hashCode());
        result = prime * result + ((refreshExpiresIn == null) ? 0 : refreshExpiresIn.hashCode());
        result = prime * result + ((refreshToken == null) ? 0 : refreshToken.hashCode());
        result = prime * result + ((scope == null) ? 0 : scope.hashCode());
        result = prime * result + ((token == null) ? 0 : token.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AccessToken other = (AccessToken) obj;
        if (expiresIn == null) {
            if (other.expiresIn != null)
                return false;
        } else if (!expiresIn.equals(other.expiresIn))
            return false;
        if (refreshExpiresIn == null) {
            if (other.refreshExpiresIn != null)
                return false;
        } else if (!refreshExpiresIn.equals(other.refreshExpiresIn))
            return false;
        if (refreshToken == null) {
            if (other.refreshToken != null)
                return false;
        } else if (!refreshToken.equals(other.refreshToken))
            return false;
        if (scope == null) {
            if (other.scope != null)
                return false;
        } else if (!scope.equals(other.scope))
            return false;
        if (token == null) {
            if (other.token != null)
                return false;
        } else if (!token.equals(other.token))
            return false;
        if (type == null) {
            if (other.type != null)
                return false;
        } else if (!type.equals(other.type))
            return false;
        return true;
    }
}
