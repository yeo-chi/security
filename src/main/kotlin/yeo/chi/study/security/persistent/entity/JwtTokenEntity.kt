package yeo.chi.study.security.persistent.entity

import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType.IDENTITY
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.apache.commons.lang3.StringUtils
import java.time.LocalDateTime
import java.time.LocalDateTime.now

@Entity
@Table(name = "jwt_token")
class JwtTokenEntity(
    @Id
    @GeneratedValue(strategy = IDENTITY)
    val id: Long = 0,

    var accessToken: String,

    val refreshToken: String,

    val expiredAt: LocalDateTime,
) {
    fun valid(refreshToken: String) {
        require(StringUtils.equals(this.refreshToken, refreshToken))
        require(expiredAt.isAfter(now()))
    }
}
