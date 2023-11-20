package yeo.chi.study.security.controller.api

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus.CREATED
import org.springframework.http.HttpStatus.OK
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import yeo.chi.study.security.configuration.TokenProvider
import yeo.chi.study.security.controller.api.data.ReIssueRequest
import yeo.chi.study.security.controller.api.data.SignInUserRequest
import yeo.chi.study.security.controller.api.data.SignUpUserRequest
import yeo.chi.study.security.persistent.entity.UserEntity
import yeo.chi.study.security.service.UserService
import java.security.Principal

@RestController
@RequestMapping("api/v1/users")
class UserApiController(
    private val userService: UserService,

    private val bCryptPasswordEncoder: BCryptPasswordEncoder,

    private val tokenProvider: TokenProvider,
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

    @PostMapping("signIn")
    @ResponseStatus(OK)
    fun signIn(@RequestBody signInUserRequest: SignInUserRequest, httpServletResponse: HttpServletResponse) {
        require(signInUserRequest.userId.isNotEmpty() && signInUserRequest.password.isNotEmpty())

        with(userService.signIn(request = signInUserRequest)) {
            httpServletResponse.addCookie(
                Cookie("access_token", accessToken).apply {
                    path = "/"
                    isHttpOnly = true
                }
            )

            httpServletResponse.addCookie(
                Cookie("refresh_token", refreshToken).apply {
                    path = "/"
                    isHttpOnly = true
                }
            )
        }
    }

    @PostMapping("reIssue")
    @ResponseStatus(OK)
    fun reIssue(@RequestBody reIssueRequest: ReIssueRequest, httpServletResponse: HttpServletResponse) {
        require(reIssueRequest.accessToken.isNotEmpty() && reIssueRequest.refreshToken.isNotEmpty())

        httpServletResponse.addCookie(
            tokenProvider.reIssue(reIssueRequest = reIssueRequest)
                .let {
                    Cookie("access_token", it.accessToken).apply {
                        path = "/"
                        isHttpOnly = true
                    }
                }
        )
    }

    @GetMapping("me")
    fun getMe(principal: Principal): String {
        return principal.name
    }
}
