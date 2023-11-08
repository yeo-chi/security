package yeo.chi.study.security.persistent.entity

import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType.IDENTITY
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import yeo.chi.study.security.controller.api.data.SignUpUserRequest

@Entity
@Table(name = "user")
class UserEntity(
    @Id
    @GeneratedValue(strategy = IDENTITY)
    val id: Long = 0,

    val userId: String,

    val password: String,
) {
    companion object {
        fun of(request: SignUpUserRequest, encoder: BCryptPasswordEncoder): UserEntity {
            return UserEntity(
                userId = request.userId,
                password = encoder.encode(request.password),
            )
        }
    }
}
