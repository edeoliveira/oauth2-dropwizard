# OAuth2-DropWizard

OAuth2-DropWizard is a dropwizard 0.8.1 implementation of an OAuth2 secured RESTful server.

It provides the /oauth20 endpoint to manage oauth authentication. Authentication token is stored in an encrypted cookie on the client. This provides automatic authentication propagation on subsequent access to protected resources without any further coding effort which is awesome as DropWizard is stateless for performance reasons.

### Version
1.0

### Tech

OAuth2-DropWizard uses a number of open source projects to work properly:

* [DropWizard] - Dropwizard is a Java framework for developing ops-friendly, high-performance, RESTful web services
* [APIFest OAuht2 server] - A server that implements OAuth 2.0 server side as per http://tools.ietf.org/html/rfc6749

[DropWizard]:http://www.dropwizard.io/
[APIFest OAuht2 server]:https://github.com/edeoliveira/apifest-oauth20