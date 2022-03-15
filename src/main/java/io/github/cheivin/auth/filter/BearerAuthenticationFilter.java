package io.github.cheivin.auth.filter;

import io.github.cheivin.auth.authentication.AuthenticationErrorHandler;
import io.github.cheivin.auth.token.TokenStore;
import io.github.cheivin.auth.user.UserDetailsService;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Bearer类型token验证
 */
public class BearerAuthenticationFilter extends AuthenticationFilter {
    public BearerAuthenticationFilter(UserDetailsService userDetailsService, TokenStore tokenStore, AuthenticationErrorHandler errorHandler) {
        super(userDetailsService, tokenStore, errorHandler);
    }

    @Override
    public Optional<String> getToken(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (StringUtils.isEmpty(token) || token.length()<7) {
            return Optional.empty();
        }
        String prefix = token.substring(0, 6);
        if (prefix.equalsIgnoreCase("bearer")) {
            token = token.substring(7);
        }
        return Optional.of(token);
    }
}
