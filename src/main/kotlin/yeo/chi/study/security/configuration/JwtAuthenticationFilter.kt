package yeo.chi.study.security.configuration

import jakarta.servlet.FilterChain
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

    private final val REISSUE_URI: String = "api/v1/users/reIssue"

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        if (!StringUtils.equals(request.requestURI, REISSUE_URI)) {
            val token = parseBearerToken(request)
            val user = parseIdentificationInformation(token)

            UsernamePasswordAuthenticationToken(user, token, user.authorities)
                .apply {
                    details = WebAuthenticationDetails(request)
                    SecurityContextHolder.getContext().authentication = this
                }
        }

        filterChain.doFilter(request, response)
    }

    private fun parseBearerToken(request: HttpServletRequest): String {
        return (request.getHeader(AUTHORIZATION) ?: ANONYMOUS)
            .takeIf { it.startsWith("Bearer ", true) }
            ?.substring(7)
            ?: ANONYMOUS
    }

    private fun parseIdentificationInformation(token: String): User {
        return (token.takeUnless { StringUtils.equals(it, ANONYMOUS) }
            ?.let { tokenProvider.validToken(token = it) }
            ?: "${ANONYMOUS}:${ANONYMOUS}")
            .split(":")
            .let { User(it[0], "", listOf(SimpleGrantedAuthority(it[1]))) }
    }
}
