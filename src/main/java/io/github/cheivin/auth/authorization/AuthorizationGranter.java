package io.github.cheivin.auth.authorization;

/**
 * 授权器
 */
public interface AuthorizationGranter {

    boolean authorize(String namespace, String privilege, CheckPoint checkPoint);
}
