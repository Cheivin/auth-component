package io.github.cheivin.auth.authentication;

import io.github.cheivin.auth.filter.AuthenticationFilter;
import io.github.cheivin.auth.filter.BearerAuthenticationFilter;
import io.github.cheivin.auth.token.TokenStore;
import io.github.cheivin.auth.user.UserDetailsService;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 身份认证管理器
 */
public class AuthenticationManager extends FilterRegistrationBean<AuthenticationFilter> {
    private static final List<String> DEFAULT_PATTERNS = Collections.singletonList("/**");
    private static final List<String> DEFAULT_EXCLUDE_PATTERNS = Collections.emptyList();

    private AuthenticationManager(UserDetailsService userDetailsService, TokenStore tokenStore, AuthenticationErrorHandler errorHandler, List<String> patterns, List<String> excludePathPatterns) {
        super();
        AuthenticationFilter filter = new BearerAuthenticationFilter(userDetailsService, tokenStore, errorHandler);
        filter.addPathPatterns(patterns == null ? DEFAULT_PATTERNS : patterns);
        filter.addExcludePathPatterns(excludePathPatterns == null ? DEFAULT_EXCLUDE_PATTERNS : excludePathPatterns);

        this.setFilter(filter);
        this.setUrlPatterns(Collections.singleton("/*"));
        this.setName("AuthenticationFilter");
        this.setOrder(1);  //值越小，Filter越靠前。
    }

    public static Builder builder(UserDetailsService userDetailsService, TokenStore tokenStore) {
        return new Builder(userDetailsService, tokenStore);
    }

    public static class Builder {
        private final UserDetailsService userDetailsService;
        private final TokenStore tokenStore;
        private List<String> patterns = new ArrayList<>();
        private List<String> excludePathPatterns = new ArrayList<>();
        private AuthenticationErrorHandler errorHandler = (request, response, e) -> {
            e.printStackTrace();
            try {
                response.sendError(HttpStatus.UNAUTHORIZED.value(), e.getMessage());
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        };

        public Builder(UserDetailsService userDetailsService, TokenStore tokenStore) {
            this.userDetailsService = userDetailsService;
            this.tokenStore = tokenStore;
        }

        public Builder setPatterns(String... patterns) {
            return setPatterns(Arrays.asList(patterns));
        }

        public Builder setPatterns(List<String> patterns) {
            this.patterns = patterns;
            return this;
        }

        public Builder addPatterns(String... patterns) {
            return addPatterns(Arrays.asList(patterns));
        }

        public Builder addPatterns(List<String> patterns) {
            this.patterns.addAll(patterns);
            return this;
        }

        public Builder setExcludePathPatterns(String... excludePathPatterns) {
            this.excludePathPatterns = Arrays.asList(excludePathPatterns);
            return this;
        }

        public Builder setExcludePathPatterns(List<String> excludePathPatterns) {
            this.excludePathPatterns = excludePathPatterns;
            return this;
        }

        public Builder setErrorHandler(AuthenticationErrorHandler errorHandler) {
            this.errorHandler = errorHandler;
            return this;
        }

        public AuthenticationManager build() {
            return new AuthenticationManager(userDetailsService, tokenStore, errorHandler, patterns, excludePathPatterns);
        }
    }
}
