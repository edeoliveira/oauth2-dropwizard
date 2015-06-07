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

package org.edeoliveira.oauth2.dropwizard.resources;

import com.codahale.metrics.annotation.Timed;
import com.google.common.base.Optional;
import io.dropwizard.auth.Auth;
import org.edeoliveira.oauth2.dropwizard.oauth2.User;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A basic resource that demonstrates authentication use.
 *
 * @author Edouard De Oliveira
 */
@Path(value = "/hello")
@Produces(MediaType.APPLICATION_JSON)
public class HelloResource {
    private final String template;
    private final String defaultName;
    private final AtomicLong counter;

    public HelloResource(String template, String defaultName) {
        this.template = template;
        this.defaultName = defaultName;
        this.counter = new AtomicLong();
    }

    @GET
    @Timed
    public Saying sayHello(@Auth User user) {
        final String value = String.format("Hello %s, you've been successfully authenticated !", user.getName());
        return new Saying(counter.incrementAndGet(), value);
    }

    @GET
    @Timed
    @Path(value = "/test")
    public Saying sayHelloToUnauthenticatedUser(@QueryParam("name") Optional<String> name) {
        final String value = String.format(template, name.or(defaultName));
        return new Saying(counter.incrementAndGet(), value);
    }
}
