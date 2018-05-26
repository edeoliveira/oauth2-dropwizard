package org.edeoliveira.oauth2.dropwizard.oauth2.apifest;

/**
 * Paths of the ApiFest Oauth2 server api to handle token issuing and validation.
 *
 * @author Edouard De Oliveira
 */
public enum ApifestApiPath {
    TOKENS("/tokens"), TOKENS_VALIDATION("/tokens/validate?token=");

    private String path;

    ApifestApiPath(String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
