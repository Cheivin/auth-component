package io.github.cheivin.auth.authentication;

import io.github.cheivin.auth.exception.TokenExpiredException;
import io.github.cheivin.auth.exception.TokenInvalidException;
import io.github.cheivin.auth.exception.TokenNotPresentException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public interface AuthenticationErrorHandler {

    default void onTokenNotPresent(HttpServletRequest request, HttpServletResponse response, TokenNotPresentException e)  throws IOException{
        onTokenInvalid(request, response, e);
    }

    default void onTokenExpired(HttpServletRequest request, HttpServletResponse response, TokenExpiredException e) throws IOException {
        onTokenInvalid(request, response, e);
    }

    void onTokenInvalid(HttpServletRequest request, HttpServletResponse response, TokenInvalidException e) throws IOException;
}
