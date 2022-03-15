package io.github.cheivin.auth.token;

import io.github.cheivin.auth.exception.TokenExpiredException;
import io.github.cheivin.auth.exception.TokenInvalidException;
import io.github.cheivin.auth.exception.TokenNotPresentException;
import io.github.cheivin.auth.user.UserDetails;
import io.jsonwebtoken.*;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * JWT-token管理器
 */
public class JwtTokenStore implements TokenStore {
    /**
     * accessToken默认过期时间，1天
     */
    protected static final long ACCESS_EXPIRE = 86400;
    /**
     * refreshToken默认过期时间，7天
     */
    protected static final long REFRESH_EXPIRE = 604800;

    protected static final String ACCESS_AUDIENCE = "access_token";
    protected static final String REFRESH_AUDIENCE = "refresh_token";

    /**
     * 加密密钥
     */
    private final String secret;
    private final long accessExpire;
    private final long refreshExpire;
    /**
     * 严格模式，accessToken只能访问验证使用，refreshToken只能刷新token使用
     */
    private final boolean strict;

    /**
     * iss(issuer): jwt签发者
     * sub(subject): jwt所面向的用户
     * aud(audience): 接收jwt的一方, 受众
     * exp(expiration time): jwt的过期时间，这个过期时间必须要大于签发时间
     * nbf(Not Before): 生效时间，定义在什么时间之前.
     * iat(Issued At): jwt的签发时间
     * jti(JWT ID): jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
     */

    private JwtTokenStore(String secret, long accessExpire, long refreshExpire, boolean strict) {
        this.secret = secret;
        this.accessExpire = accessExpire;
        this.refreshExpire = refreshExpire;
        this.strict = strict;
    }

    public static Builder builder(String secret) {
        return new Builder(secret);
    }

    private Date dateAfter(long second) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, Math.toIntExact(second));
        return calendar.getTime();
    }


    /**
     * 解析token
     *
     * @param token token
     * @return token解析结果
     * @throws TokenInvalidException token不可用
     */
    private Claims parseToken(String token) throws TokenInvalidException {
        if (!StringUtils.hasText(token)) {
            throw new TokenNotPresentException();
        }
        try {
            return Jwts.parser().setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException(token, e.getClaims().getExpiration(), e);
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException e) {
            throw new TokenInvalidException(token, e);
        }
    }

    private Token createToken(Claims baseClaims, String audience, long ttl) {
        return Token.builder()
                .token(Jwts.builder()
                        .signWith(SignatureAlgorithm.HS256, secret)
                        .setClaims(Jwts.claims(baseClaims))
                        .setAudience(audience)
                        .setExpiration(dateAfter(ttl))
                        .compact())
                .expiresIn(ttl)
                .build();
    }

    @Override
    public AuthenticationToken createToken(UserDetails userDetails) {
        Claims baseClaims = Jwts.claims().setSubject(String.valueOf(userDetails.getUid()));
        baseClaims.put("user", userDetails);
        return AuthenticationToken.builder()
                .accessToken(createToken(baseClaims, ACCESS_AUDIENCE, accessExpire))
                .refreshToken(createToken(baseClaims, REFRESH_AUDIENCE, refreshExpire))
                .build();
    }

    @Override
    public AuthenticationToken refreshToken(String refreshToken, UserDetails userDetails) throws TokenInvalidException {
        Claims claims = parseToken(refreshToken);
        if (strict) {
            if (!REFRESH_AUDIENCE.equals(claims.getAudience())) {
                throw new TokenInvalidException(refreshToken, "Token store is strict mode. current aud is:" + claims.getAudience()
                        + ", but allowed aud is:" + REFRESH_AUDIENCE);
            }
        }
        Claims baseClaims = Jwts.claims().setSubject(String.valueOf(userDetails.getUid()));
        baseClaims.put("user", userDetails);
        AuthenticationToken token = AuthenticationToken.builder()
                .accessToken(createToken(baseClaims, ACCESS_AUDIENCE, accessExpire))
                .build();
        // 判断是否需要刷新refreshToken
        Date expireAt = claims.getExpiration();
        long remainingTime = ChronoUnit.SECONDS.between(Instant.now(), expireAt.toInstant());
        // 小于access存活时间才刷新
        if (remainingTime <= accessExpire) {
            token.setRefreshToken(createToken(baseClaims, REFRESH_AUDIENCE, refreshExpire));
        } else {
            token.setRefreshToken(Token.builder()
                    .token(refreshToken)
                    .expiresIn(remainingTime)
                    .build());
        }
        return token;
    }


    @Override
    public Optional<Long> verifyAccessToken(String accessToken) throws TokenInvalidException {
        Claims claims = parseToken(accessToken);
        if (strict) {
            if (!ACCESS_AUDIENCE.equals(claims.getAudience())) {
                throw new TokenInvalidException(accessToken, "Token store is strict mode. current aud is:" + claims.getAudience()
                        + ", but allowed aud is:" + ACCESS_AUDIENCE);
            }
        }
        Date expireAt = claims.getExpiration();
        return Optional.of(ChronoUnit.SECONDS.between(Instant.now(), expireAt.toInstant()));
    }


    @SuppressWarnings("unchecked")
    @Override
    public UserDetails getUserDetailsByToken(String accessToken) throws TokenInvalidException {
        Claims claims = parseToken(accessToken);
        Map<String, Object> detailMap = (Map<String, Object>) claims.get("user");
        List<String> roleList = (List<String>) detailMap.get("roles");
        Object uid = detailMap.get("uid");
        Object name = detailMap.get("name");
        return UserDetails.builder()
                .uid(uid == null ? null : (String) uid)
                .name(name == null ? null : (String) name)
                .roles(roleList.toArray(new String[]{}))
                .attributes((Map<String, String>) detailMap.get("attributes"))
                .token(accessToken)
                .build();
    }

    public static class Builder {
        private final String secret;
        private long accessExpire = ACCESS_EXPIRE; // 1天
        private long refreshExpire = REFRESH_EXPIRE; // 7天
        private boolean strict = true; // 严格模式

        public Builder(String secret) {
            this.secret = secret;
        }

        public Builder setAccessExpire(long accessExpire) {
            this.accessExpire = accessExpire;
            return this;
        }

        public Builder setRefreshExpire(long refreshExpire) {
            this.refreshExpire = refreshExpire;
            return this;
        }

        public Builder setStrict(boolean strict) {
            this.strict = strict;
            return this;
        }

        public JwtTokenStore build() {
            return new JwtTokenStore(secret, accessExpire, refreshExpire, strict);
        }
    }

    public static void main(String[] args) throws TokenInvalidException {
        JwtTokenStore tokenStore = JwtTokenStore.builder("test").build();
        UserDetails userDetails = UserDetails.builder()
                .uid("4f2d9b094f934ad1a359f66df83f813b")
                .roles(new String[]{"NORMAL", "MANAGER"})
                .build();
        AuthenticationToken token = tokenStore.createToken(userDetails);
        System.out.println(tokenStore.getUserDetailsByToken(token.getAccessToken().getToken()));
//        tokenStore.refreshToken(token.getRefreshToken().getToken(), userDetails);
    }
}
