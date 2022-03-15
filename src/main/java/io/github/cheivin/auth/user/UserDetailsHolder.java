package io.github.cheivin.auth.user;

import java.util.Optional;

/**
 *
 */
public class UserDetailsHolder {
    private static final InheritableThreadLocal<UserDetails> currUser = new InheritableThreadLocal<>();

    /**
     * 获取当前用户
     *
     * @return 用户
     */
    public static Optional<UserDetails> currentUser() {
        return Optional.ofNullable(currUser.get());
    }

    public static void init(UserDetails userDetails) {
        currUser.set(userDetails);
    }

    public static void invalid() {
        currUser.remove();
    }

    public static boolean hasRole(String role) {
        if (currentUser().isPresent()) {
            UserDetails details = currentUser().get();
            for (String detailsRole : details.getRoles()) {
                if (detailsRole.equals(role)) {
                    return true;
                }
            }
        }
        return false;
    }
}
