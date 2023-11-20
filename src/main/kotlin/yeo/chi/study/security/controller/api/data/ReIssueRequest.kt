package yeo.chi.study.security.controller.api.data

data class ReIssueRequest(
    val accessToken: String,

    val refreshToken: String,
)
