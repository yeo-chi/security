package yeo.chi.study.security.configuration

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import yeo.chi.study.security.persistent.entity.UserEntity
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

    @Value("\${jwt.expiration-second}")
    private val expirationSecond: Long,
) {
    fun createToken(userEntity: UserEntity): String {
        return userEntity.let {
            Jwts.builder()
                .subject(getIdentificationInformation(it))
                .issuer(issuer)
                .issuedAt(Timestamp.valueOf(now()))
                .expiration(Date.from(Instant.now().plusSeconds(expirationSecond)))
                .signWith(SecretKeySpec(secretKey.toByteArray(), SignatureAlgorithm.HS512.jcaName))
                .compact()!!
        }
    }

    private fun getIdentificationInformation(userEntity: UserEntity) = userEntity.userId + ":" + Role.USER
}
