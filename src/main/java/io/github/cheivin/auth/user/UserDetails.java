package io.github.cheivin.auth.user;

import lombok.*;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class UserDetails implements Principal {
    /**
     * 用户ID
     */
    private String uid;
    /**
     * 用户名称
     */
    private String name;
    /**
     * 角色身份
     */
    private String[] roles;
    /**
     * 属性
     */
    private Map<String, String> attributes;
    /**
     * 当前token
     */
    private transient String token;

    public String[] getRoles() {
        if (roles == null) {
            return new String[0];
        }
        return roles;
    }

    public Map<String, String> getAttributes() {
        if (attributes == null) {
            return new HashMap<>(0);
        }
        return attributes;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
