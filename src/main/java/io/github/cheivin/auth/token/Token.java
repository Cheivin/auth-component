package io.github.cheivin.auth.token;

import lombok.*;

/**
 * token信息
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class Token {
    /**
     * token字符串
     */
    private String token;
    /**
     * 过期时间
     */
    private long expiresIn;
}
