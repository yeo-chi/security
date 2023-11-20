package yeo.chi.study.security.service

import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service
import yeo.chi.study.security.configuration.Role.USER
import yeo.chi.study.security.configuration.TokenProvider
import yeo.chi.study.security.controller.api.data.SignInUserRequest
import yeo.chi.study.security.persistent.entity.JwtTokenEntity
import yeo.chi.study.security.persistent.entity.UserEntity
import yeo.chi.study.security.persistent.repository.JwtTokenRepository
import yeo.chi.study.security.persistent.repository.UserRepository

@Service
class UserService(
    private val userRepository: UserRepository,

    private val passwordEncoder: BCryptPasswordEncoder,

    private val tokenProvider: TokenProvider,

    private val jwtTokenRepository: JwtTokenRepository,
) {
    fun createUser(user: UserEntity) {
        userRepository.save(user)
    }

    fun signIn(request: SignInUserRequest): JwtTokenEntity {
        val user = userRepository.findByUserId(userId = request.userId)
            ?: throw UsernameNotFoundException("회원을 찾을 수 없습니다.")

        return user.also { it.validPassword(password = request.password, passwordEncoder = passwordEncoder) }
            .let { tokenProvider.createToken(userId = it.id, role = USER) }
            .apply { jwtTokenRepository.save(this) }
    }
}
