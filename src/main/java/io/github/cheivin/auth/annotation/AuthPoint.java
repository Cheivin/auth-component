package io.github.cheivin.auth.annotation;


import java.lang.annotation.*;

/**
 * 方法权限注解
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface AuthPoint {
    /**
     * 权限名称
     */
    String privilege();

    /**
     * 权限组
     */
    String namespace() default "";

    /**
     * 忽略权限
     */
    boolean ignore() default false;

}
