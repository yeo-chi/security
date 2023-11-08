package yeo.chi.study.security.controller.api

import org.springframework.http.HttpStatus.CREATED
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import yeo.chi.study.security.controller.api.data.SignUpUserRequest
import yeo.chi.study.security.persistent.entity.UserEntity
import yeo.chi.study.security.service.UserService
import java.security.Principal

@RestController
@RequestMapping("api/v1/users")
class UserApiController(
    private val userService: UserService,

    private val bCryptPasswordEncoder: BCryptPasswordEncoder,
) {
    @PostMapping
    @ResponseStatus(CREATED)
    fun signUp(@RequestBody signUpUserRequest: SignUpUserRequest) {
        userService.createUser(
            user = UserEntity.of(
                request = signUpUserRequest,
                encoder = bCryptPasswordEncoder,
            ),
        )
    }

    @GetMapping("me")
    fun getMe(principal: Principal) {
        println(principal.name)
    }
}
