package yeo.chi.study.security.controller.web

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

@Controller
class WebController {
    @GetMapping
    fun main() = "main"

    @GetMapping("/login")
    fun login() = "login"
}
