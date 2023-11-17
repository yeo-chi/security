package yeo.chi.study.security.configuration

import org.springframework.security.web.session.SessionInformationExpiredEvent
import org.springframework.security.web.session.SessionInformationExpiredStrategy
import org.springframework.stereotype.Component

@Component
class SessionLogoutStrategy : SessionInformationExpiredStrategy {
    override fun onExpiredSessionDetected(event: SessionInformationExpiredEvent?) {
        checkNotNull(event)

        event.response.sendRedirect("/login")
    }
}
