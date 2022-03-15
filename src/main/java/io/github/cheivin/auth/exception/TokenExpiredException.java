package io.github.cheivin.auth.exception;

import java.util.Date;

/**
 * token过期
 */
public class TokenExpiredException extends TokenInvalidException {
    private final Date expiredAt;

    public TokenExpiredException(String token, Date expiredAt) {
        super(token);
        this.expiredAt = expiredAt;
    }

    public TokenExpiredException(String token, Date expiredAt, Throwable cause) {
        super(token, cause);
        this.expiredAt = expiredAt;
    }

    public Date getExpiredAt() {
        return expiredAt;
    }
}
