# OAuth2-DropWizard

OAuth2-DropWizard is a dropwizard 0.8.x implementation of an OAuth2 secured RESTful server.

It provides the /oauth20 endpoint to manage oauth authentication. Authentication token is stored in an encrypted cookie on the client. This provides automatic authentication propagation on subsequent accesses to protected resources by just using the generated client cookie.

Using this cookie, a client browser (or any web/mobile app), which is by nature insecure, can then securely handle it's user's credentials and access a stateless server like DropWizard in a secure manner (no credentials stored in the sources or handled by javascript).

### Version
1.0

### Tech

OAuth2-DropWizard uses a number of open source projects to work properly:

* [DropWizard] - Dropwizard is a Java framework for developing ops-friendly, high-performance, RESTful web services
* [APIFest OAuth2 server] - A server that implements OAuth 2.0 server side as per http://tools.ietf.org/html/rfc6749 (using  an extensively modified fork i worked on)

[DropWizard]:http://www.dropwizard.io/
[APIFest OAuth2 server]:https://github.com/edeoliveira/apifest-oauth20
