package io.github.cheivin.auth.token;

import io.github.cheivin.auth.exception.TokenInvalidException;
import io.github.cheivin.auth.user.UserDetails;

import java.util.Optional;

/**
 * token管理器
 */
public interface TokenStore {

    /**
     * 生成token
     *
     * @param userDetails 用户信息
     * @return token信息
     */
    AuthenticationToken createToken(UserDetails userDetails);

    /**
     * 刷新token
     *
     * @param refreshToken 刷新token
     * @param userDetails  用户信息
     * @return token信息
     * @throws TokenInvalidException token无效
     */
    AuthenticationToken refreshToken(String refreshToken, UserDetails userDetails) throws TokenInvalidException;

    /**
     * 验证token过期时间
     *
     * @param accessToken 访问token
     * @return 剩余时间，单位秒
     * @throws TokenInvalidException token无效
     */
    Optional<Long> verifyAccessToken(String accessToken) throws TokenInvalidException;

    UserDetails getUserDetailsByToken(String accessToken) throws TokenInvalidException;
}
