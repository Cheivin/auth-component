package io.github.cheivin.auth.authorization;

import io.github.cheivin.auth.annotation.AuthAspect;
import io.github.cheivin.auth.annotation.AuthPoint;
import io.github.cheivin.auth.exception.UnauthorizedException;
import io.github.cheivin.auth.user.UserDetails;
import io.github.cheivin.auth.user.UserDetailsHolder;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;

import java.lang.reflect.Method;
import java.util.Optional;

/**
 * 权限验证管理器
 */
@Aspect
@Slf4j
public class AuthorizationManager {
    /**
     * 权限管理
     */
    private final AuthorizationGranter granter;

    public AuthorizationManager(AuthorizationGranter granter) {
        this.granter = granter;
    }

    @Before("@annotation(io.github.cheivin.auth.annotation.AuthPoint) || @within(io.github.cheivin.auth.annotation.AuthAspect)")
    public void authMethod(JoinPoint joinPoint) throws UnauthorizedException {
        Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
        AuthPoint authPoint = method.getAnnotation(AuthPoint.class);
        if (authPoint != null && authPoint.ignore()) {
            return;
        }
        AuthAspect authAspect = joinPoint.getTarget().getClass().getAnnotation(AuthAspect.class);

        // 获取权限点信息
        String namespace, privilege;
        if (authPoint == null) {
            privilege = method.getName();
            namespace = authAspect.namespace();
        } else {
            privilege = authPoint.privilege();
            namespace = authPoint.namespace();
            ;
            if (authAspect != null && "".equals(namespace)) {
                namespace = authAspect.namespace();
            }
        }
        // 验证授权
        Optional<UserDetails> detailsOptional = UserDetailsHolder.currentUser();
        CheckPoint checkPoint = new CheckPoint(
                joinPoint.getSignature().getDeclaringType(),
                method,
                joinPoint.getArgs(),
                detailsOptional.orElse(null)
        );
        if (!granter.authorize(namespace, privilege, checkPoint)) {
            throw new UnauthorizedException(namespace, privilege);
        }
    }
}
