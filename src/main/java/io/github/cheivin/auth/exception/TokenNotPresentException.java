package io.github.cheivin.auth.exception;

/**
 * token不存在
 */
public class TokenNotPresentException extends TokenInvalidException {
    public TokenNotPresentException() {
        super("", "token not present");
    }

}
