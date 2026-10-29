package io.github.springauth.autoconfigure;

import java.time.Clock;

import io.github.springauth.autoconfigure.redis.RedisAccessTokenRevocationStore;
import io.github.springauth.autoconfigure.redis.RedisRateLimiter;
import io.github.springauth.autoconfigure.redis.RedisReplayGuard;
import io.github.springauth.autoconfigure.redis.RedisServerSessionStore;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.port.AccessTokenRevocationStore;
import io.github.springauth.core.port.RateLimiter;
import io.github.springauth.core.port.ReplayGuard;
import io.github.springauth.core.port.ServerSessionStore;
import io.github.springauth.core.service.ServerSessionService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Swaps the single-instance defaults for Redis-backed implementations.
 *
 * <p>Applies automatically as soon as Spring Data Redis is on the classpath and a
 * {@code StringRedisTemplate} exists, because the three concerns it covers (rate limiting, token
 * revocation and replay detection) are all wrong when each replica keeps its own state:
 * <ul>
 *   <li>a per-instance quota multiplies by the number of replicas;</li>
 *   <li>a logout only takes effect on the instance that handled it;</li>
 *   <li>a replayed token is undetected on any other instance.</li>
 * </ul>
 *
 * <p>Ordered before the core configuration so its beans win the {@code @ConditionalOnMissingBean}
 * race. Set {@code spring-auth.redis.enabled=false} to keep the in-memory ones anyway.
 */
@AutoConfiguration(before = SpringAuthAutoConfiguration.class, after = DataRedisAutoConfiguration.class)
@ConditionalOnClass(StringRedisTemplate.class)
@ConditionalOnBean(StringRedisTemplate.class)
@ConditionalOnProperty(prefix = "spring-auth.redis", name = "enabled", havingValue = "true",
        matchIfMissing = true)
public class SpringAuthRedisAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(RateLimiter.class)
    public RateLimiter springAuthRedisRateLimiter(StringRedisTemplate redis, Clock clock) {
        return new RedisRateLimiter(redis, clock);
    }

    @Bean
    @ConditionalOnMissingBean(AccessTokenRevocationStore.class)
    public AccessTokenRevocationStore springAuthRedisRevocationStore(StringRedisTemplate redis) {
        return new RedisAccessTokenRevocationStore(redis);
    }

    @Bean
    @ConditionalOnMissingBean(ReplayGuard.class)
    public ReplayGuard springAuthRedisReplayGuard(StringRedisTemplate redis) {
        return new RedisReplayGuard(redis);
    }

    @Bean
    @ConditionalOnMissingBean(ServerSessionStore.class)
    public ServerSessionStore springAuthRedisSessionStore(StringRedisTemplate redis) {
        return new RedisServerSessionStore(redis);
    }

    @Bean
    @ConditionalOnMissingBean(ServerSessionService.class)
    public ServerSessionService springAuthServerSessionService(ServerSessionStore store,
                                                                 Clock clock,
                                                                 AuthProperties properties) {
        return new ServerSessionService(store, clock,
                properties.getSession().getInactivityTtl(),
                properties.getSession().getAbsoluteTtl());
    }
}
