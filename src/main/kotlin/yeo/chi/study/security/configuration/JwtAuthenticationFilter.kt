package yeo.chi.study.security.configuration

import jakarta.servlet.FilterChain
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.apache.commons.lang3.StringUtils
import org.springframework.http.HttpHeaders.AUTHORIZATION
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.WebAuthenticationDetails
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    private val tokenProvider: TokenProvider,
) : OncePerRequestFilter() {
    private final val ANONYMOUS: String = "ANONYMOUS"

    private final val IDENTIFY: String = "identify"

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val token = parseBearerToken(request)
        val identify = getCookieValueByKey(cookies = request.cookies, key = IDENTIFY)
        val user = parseIdentificationInformation(token, identify)

        UsernamePasswordAuthenticationToken(user, token, user.authorities)
            .apply {
                details = WebAuthenticationDetails(request)
                SecurityContextHolder.getContext().authentication = this
            }

        filterChain.doFilter(request, response)
    }

    private fun getCookieValueByKey(cookies: Array<Cookie>, key: String): String {
        return cookies.associate { it.name to it.value }[key] ?: ""
    }

    private fun parseBearerToken(request: HttpServletRequest): String {
        return (request.getHeader(AUTHORIZATION) ?: ANONYMOUS)
            .takeIf { it.startsWith("Bearer ", true) }
            ?.substring(7)
            ?: ANONYMOUS
    }

    private fun parseIdentificationInformation(token: String, identify: String): User {
        return (token.takeUnless { StringUtils.equals(it, ANONYMOUS) }
            ?.let { tokenProvider.getSubject(token = it, identify = identify) }
            ?: "${ANONYMOUS}:${ANONYMOUS}")
            .split(":")
            .let { User(it[0], "", listOf(SimpleGrantedAuthority(it[1]))) }
    }
}
