package yeo.chi.study.security.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfiguration(
    private val sessionLogoutStrategy: SessionLogoutStrategy,
) {
    @Bean
    fun filterChain(httpSecurity: HttpSecurity): SecurityFilterChain {
        return httpSecurity
            .csrf { it.disable() }
            .authorizeHttpRequests {
                it.requestMatchers("/api/v1/users/signIn", "/api/v1/users").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin {
                it.loginPage("/login")
                    .usernameParameter("userId")
                    .passwordParameter("password")
                    .loginProcessingUrl("/api/v1/users/signIn")
                    .defaultSuccessUrl("/")
                    .permitAll()
            }
            .sessionManagement {
                it.sessionFixation { sessionFixation ->
                    sessionFixation.changeSessionId()
                }
                it.maximumSessions(1)
                    .expiredSessionStrategy(sessionLogoutStrategy)
                    .maxSessionsPreventsLogin(false)
                    .sessionRegistry(sessionRegistry())
            }
            .build()
    }

    @Bean
    fun bCryptPasswordEncoder() = BCryptPasswordEncoder()

    @Bean
    fun sessionRegistry() = SessionRegistryImpl()
}
