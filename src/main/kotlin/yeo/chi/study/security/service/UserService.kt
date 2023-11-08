package yeo.chi.study.security.service

import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import yeo.chi.study.security.persistent.entity.UserEntity
import yeo.chi.study.security.persistent.repository.UserRepository

@Service
class UserService(
    private val userRepository: UserRepository,
) : UserDetailsService {
    override fun loadUserByUsername(userId: String?): UserDetails {
        require(!userId.isNullOrEmpty())

        return userRepository.findByUserId(userId = userId)?.let {
            User(it.id.toString(), it.password, listOf())
        } ?: throw UsernameNotFoundException("회원을 찾을 수 없습니다.")
    }

    @Transactional
    fun createUser(user: UserEntity) {
        userRepository.save(user)
    }
}
