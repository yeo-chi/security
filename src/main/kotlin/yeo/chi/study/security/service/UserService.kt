package yeo.chi.study.security.service

import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service
import yeo.chi.study.security.controller.api.data.SignInUserRequest
import yeo.chi.study.security.persistent.entity.UserEntity
import yeo.chi.study.security.persistent.repository.UserRepository

@Service
class UserService(
    private val userRepository: UserRepository,

    private val passwordEncoder: BCryptPasswordEncoder,
) {
    fun createUser(user: UserEntity) {
        userRepository.save(user)
    }

    fun signIn(request: SignInUserRequest): UserEntity {
        require(request.userId.isNotEmpty() && request.password.isNotEmpty())

        return userRepository.findByUserId(userId = request.userId)
            ?.also {
                it.validPassword(
                    password = request.password,
                    passwordEncoder = passwordEncoder,
                )
            } ?: throw UsernameNotFoundException("회원을 찾을 수 없습니다.")
    }
}
