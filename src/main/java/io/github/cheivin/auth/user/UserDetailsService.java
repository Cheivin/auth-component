package io.github.cheivin.auth.user;

import java.util.Optional;

/**
 *
 */
public interface UserDetailsService {
    Optional<UserDetails> loadUserDetailsByUid(String uid);

    Optional<UserDetails> loadUserDetailsByToken(String token);
}
