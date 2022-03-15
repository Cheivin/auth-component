package io.github.cheivin.auth.exception;

/**
 * 未授权异常
 */
public class UnauthorizedException extends Exception {
    private final String privilege;
    private final String namespace;

    public UnauthorizedException(String namespace, String privilege) {
        super("Unauthorized for namespace:" + namespace + ", privilege:" + privilege);
        this.privilege = privilege;
        this.namespace = namespace;
    }

    public String getPrivilege() {
        return privilege;
    }

    public String getNamespace() {
        return namespace;
    }
}
