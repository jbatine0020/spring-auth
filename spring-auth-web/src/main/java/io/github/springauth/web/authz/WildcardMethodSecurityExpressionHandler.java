package io.github.springauth.web.authz;

import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

/**
 * Swaps the SpEL root of method security for the wildcard-aware one.
 *
 * <p>Register it as a {@code MethodSecurityExpressionHandler} bean and every
 * {@code @PreAuthorize("hasAuthority(...)")} in the application starts accepting the wildcard, with
 * no change to a single annotation.
 *
 * <p>The bean must be declared {@code static} in its configuration class. Method security is
 * initialised very early, and a non-static factory method drags its enclosing configuration into
 * that early phase, which produces "not eligible for auto-proxying" warnings and can leave other
 * post-processors out of the picture.
 */
public class WildcardMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    @Override
    public EvaluationContext createEvaluationContext(Supplier<? extends Authentication> authentication,
                                                     MethodInvocation invocation) {
        EvaluationContext context = super.createEvaluationContext(authentication, invocation);
        if (!(context instanceof StandardEvaluationContext standardContext)) {
            return context;
        }
        Object root = standardContext.getRootObject().getValue();
        if (!(root instanceof MethodSecurityExpressionOperations delegate)) {
            return context;
        }
        Authentication resolved = authentication.get();
        if (resolved == null) {
            return context;
        }
        // Pure delegation, so the collaborators configured on the handler (role hierarchy,
        // permission evaluator, trust resolver) keep applying through the standard root.
        standardContext.setRootObject(new WildcardMethodSecurityExpressionRoot(delegate, resolved));
        return standardContext;
    }
}
