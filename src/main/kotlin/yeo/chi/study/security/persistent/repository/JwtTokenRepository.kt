package yeo.chi.study.security.persistent.repository

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import yeo.chi.study.security.persistent.entity.JwtTokenEntity

@Repository
interface JwtTokenRepository : JpaRepository<JwtTokenEntity, Long> {
    fun findByAccessToken(accessToken: String): JwtTokenEntity?
}
