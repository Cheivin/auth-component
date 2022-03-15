package io.github.cheivin.auth.filter;

import io.github.cheivin.auth.user.UserDetails;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;

/**
 *
 */
public class HttpServletRequestUserDetailsWrapper extends HttpServletRequestWrapper {
    private final UserDetails userDetails;

    public HttpServletRequestUserDetailsWrapper(HttpServletRequest request, UserDetails userDetails) {
        super(request);
        this.userDetails = userDetails;
    }

    @Override
    public Principal getUserPrincipal() {
        return userDetails;
    }
}
