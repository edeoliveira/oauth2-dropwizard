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

package org.edeoliveira.oauth2.dropwizard.oauth2;

import org.edeoliveira.oauth2.dropwizard.oauth2.apifest.AccessToken;

/**
 * Holds the authenticated principal of the current user and it's token if needed when accessing other services.
 *
 * @author Edouard De Oliveira
 */
public class User {
    private String name;
    private AccessToken token;

    public User(String name, AccessToken token) {
        super();
        this.name = name;
        this.token = token;
    }

    public String getName() {
        return name;
    }

    public AccessToken getToken() {
        return token;
    }
}
