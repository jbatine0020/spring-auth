package io.github.springauth.web.stepup;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Applies {@link RequiresStepUp} before the annotated handler runs.
 *
 * <p>Running in {@code preHandle} is the point: the confirmation is checked before any business
 * write happens, so a wrong code leaves nothing behind. The {@link io.github.springauth.core.error.MfaException}
 * it lets through is turned into a response by the library's exception handler.
 */
public class StepUpInterceptor implements HandlerInterceptor {

    private final StepUpEnforcer enforcer;

    public StepUpInterceptor(StepUpEnforcer enforcer) {
        this.enforcer = enforcer;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (handler instanceof HandlerMethod method && requiresStepUp(method)) {
            enforcer.enforce(request);
        }
        return true;
    }

    private boolean requiresStepUp(HandlerMethod method) {
        return method.hasMethodAnnotation(RequiresStepUp.class)
                || method.getBeanType().isAnnotationPresent(RequiresStepUp.class);
    }
}
