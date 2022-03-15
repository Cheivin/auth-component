package io.github.cheivin.auth.token;

import lombok.*;

/**
 * 身份token信息
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class AuthenticationToken {
    /**
     * 用户token
     */
    private Token accessToken;
    /**
     * 刷新token
     */
    private Token refreshToken;

    /**
     * 固定bearer token类型
     *
     * @return token类型
     */
    public String getTokenType() {
        return "bearer";
    }
}
