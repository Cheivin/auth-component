package io.github.cheivin.auth.filter;

import io.github.cheivin.auth.authentication.AuthenticationErrorHandler;
import io.github.cheivin.auth.exception.TokenExpiredException;
import io.github.cheivin.auth.exception.TokenInvalidException;
import io.github.cheivin.auth.exception.TokenNotPresentException;
import io.github.cheivin.auth.token.TokenStore;
import io.github.cheivin.auth.user.UserDetails;
import io.github.cheivin.auth.user.UserDetailsHolder;
import io.github.cheivin.auth.user.UserDetailsService;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.util.UrlPathHelper;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

/**
 * token验证
 */
public abstract class AuthenticationFilter implements Filter {
    private final UserDetailsService userDetailsService;
    private final TokenStore tokenStore;
    private final AuthenticationErrorHandler errorHandler;

    private final LinkedHashSet<String> pathPatterns = new LinkedHashSet<>();
    private final LinkedHashSet<String> excludePathPatterns = new LinkedHashSet<>();

    private final AntPathMatcher matcher = new AntPathMatcher();
    private final UrlPathHelper pathHelper = new UrlPathHelper();

    public AuthenticationFilter(UserDetailsService userDetailsService, TokenStore tokenStore, AuthenticationErrorHandler errorHandler) {
        this.userDetailsService = userDetailsService;
        this.tokenStore = tokenStore;
        this.errorHandler = errorHandler;
    }

    public void addPathPatterns(List<String> pathPatterns) {
        this.pathPatterns.addAll(pathPatterns);
    }

    public void addPathPatterns(String... pathPatterns) {
        addPathPatterns(Arrays.asList(pathPatterns));
    }

    public void addExcludePathPatterns(List<String> excludePathPatterns) {
        this.excludePathPatterns.addAll(excludePathPatterns);
    }

    public void addExcludePathPatterns(String... excludePathPatterns) {
        addExcludePathPatterns(Arrays.asList(excludePathPatterns));
    }


    public abstract Optional<String> getToken(HttpServletRequest request);

    protected boolean isExcludePath(HttpServletRequest request) {
        String path = pathHelper.getLookupPathForRequest(request);
        for (String excludePathPattern : excludePathPatterns) {
            if (matcher.match(excludePathPattern, path)) {
                return true;
            }
        }
        return false;
    }

    protected boolean isIncludePath(HttpServletRequest request) {
        String path = pathHelper.getLookupPathForRequest(request);
        for (String pathPattern : pathPatterns) {
            if (matcher.match(pathPattern, path)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        // 判断路径
        if (!isIncludePath(request) || isExcludePath(request)) {
            chain.doFilter(request, response);
            return;
        }
        // 获取token
        Optional<String> tokenOptional = getToken(request);
        if (!tokenOptional.isPresent()) {
            errorHandler.onTokenNotPresent(request, response, new TokenNotPresentException());
            return;
        }
        // 验证token信息
        try {
            tokenStore.verifyAccessToken(tokenOptional.get());
        } catch (TokenExpiredException e) {
            errorHandler.onTokenExpired(request, response, e);
            return;
        } catch (TokenInvalidException e) {
            errorHandler.onTokenInvalid(request, response, e);
            return;
        }
        // 获取用户信息
        Optional<UserDetails> userDetailsOptional = userDetailsService.loadUserDetailsByToken(tokenOptional.get());
        if (userDetailsOptional.isPresent()) {
            UserDetails userDetails = userDetailsOptional.get();
            UserDetailsHolder.init(userDetails);
            request = new HttpServletRequestUserDetailsWrapper(request, userDetails);
        }
        try {
            chain.doFilter(request, response);
        } finally {
            UserDetailsHolder.invalid();
        }
    }
}
