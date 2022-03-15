package io.github.cheivin.auth.annotation;

import java.lang.annotation.*;

/**
 * 类权限注解
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface AuthAspect {
    /**
     * 权限组
     */
    String namespace() default "";
}
