package yeo.chi.study.security.configuration

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import yeo.chi.study.security.configuration.Role.USER
import yeo.chi.study.security.controller.api.data.ReIssueRequest
import yeo.chi.study.security.persistent.entity.JwtTokenEntity
import yeo.chi.study.security.persistent.repository.JwtTokenRepository
import java.sql.Timestamp
import java.time.Instant
import java.time.LocalDateTime.now
import java.util.*
import javax.crypto.spec.SecretKeySpec

@Component
class TokenProvider(
    @Value("\${jwt.secret-key}")
    private val secretKey: String,

    @Value("\${jwt.issuer}")
    private val issuer: String,

    @Value("\${jwt.access-token-expiration-second}")
    private val accessTokenExpirationSecond: Long,

    @Value("\${jwt.refresh-token-expiration-second}")
    private val refreshTokenExpirationSecond: Long,

    private val jwtTokenRepository: JwtTokenRepository,
) {
    fun createToken(userId: Long, role: Role): JwtTokenEntity {
        return JwtTokenEntity(
            accessToken = Jwts.builder()
                .subject(getIdentificationInformation(userId = userId, role = role))
                .issuer(issuer)
                .issuedAt(Timestamp.valueOf(now()))
                .expiration(Date.from(Instant.now().plusSeconds(accessTokenExpirationSecond)))
                .signWith(SecretKeySpec(secretKey.toByteArray(), SignatureAlgorithm.HS512.jcaName))
                .compact()!!,
            refreshToken = Jwts.builder()
                .subject(userId.toString())
                .expiration(Date.from(Instant.now().plusSeconds(refreshTokenExpirationSecond)))
                .signWith(SecretKeySpec(secretKey.toByteArray(), SignatureAlgorithm.HS512.jcaName))
                .compact()!!,
            expiredAt = now().plusSeconds(refreshTokenExpirationSecond),
        )
    }

    private fun getIdentificationInformation(userId: Long, role: Role) = "${userId}:${role}"

    fun validToken(token: String): String {
        return Jwts.parser()
            .verifyWith(SecretKeySpec(secretKey.toByteArray(), SignatureAlgorithm.HS512.jcaName))
            .build()
            .parseSignedClaims(token)
            .payload
            .subject
    }

    @Transactional
    fun reIssue(reIssueRequest: ReIssueRequest): JwtTokenEntity {
        return jwtTokenRepository.findByAccessToken(accessToken = reIssueRequest.accessToken)
            ?.also { it.valid(reIssueRequest.refreshToken) }
            ?.apply { accessToken = createToken(userId = validToken(refreshToken).toLong(), role = USER).accessToken }
            ?: throw IllegalArgumentException()
    }
}
