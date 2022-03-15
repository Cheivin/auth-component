package io.github.cheivin.auth.authorization;

import io.github.cheivin.auth.user.UserDetails;

import java.lang.reflect.Method;

/**
 *
 */
public class CheckPoint {
    private final Class<?> target;
    private final Method method;
    private final Object[] args;
    private final UserDetails userDetails;

    public CheckPoint(Class<?> target, Method method, Object[] args, UserDetails userDetails) {
        this.target = target;
        this.method = method;
        this.args = args;
        this.userDetails = userDetails;
    }

    public Class<?> getTarget() {
        return target;
    }

    public Method getMethod() {
        return method;
    }

    public Object[] getArgs() {
        return args;
    }

    public UserDetails getUserDetails() {
        return userDetails;
    }
}
