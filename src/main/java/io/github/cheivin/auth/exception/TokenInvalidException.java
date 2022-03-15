package io.github.cheivin.auth.exception;

/**
 * token无效
 */
public class TokenInvalidException extends Exception {
    private final String token;

    public TokenInvalidException(String token) {
        this.token = token;
    }

    public TokenInvalidException(String token, String message) {
        super(message);
        this.token = token;
    }

    public TokenInvalidException(String token, Throwable cause) {
        super(cause);
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
