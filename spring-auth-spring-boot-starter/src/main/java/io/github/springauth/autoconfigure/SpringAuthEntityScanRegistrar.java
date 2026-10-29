package io.github.springauth.autoconfigure;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.boot.autoconfigure.AutoConfigurationPackages;
import org.springframework.boot.persistence.autoconfigure.EntityScanPackages;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;

/**
 * Makes the library's JPA entities visible to the application's entity manager.
 *
 * <p>Entities live in the library's own package, which the application's component scan never
 * reaches. The obvious fix, putting {@code @EntityScan} on an auto-configuration, quietly breaks
 * the host: Spring Boot scans the auto-configuration packages <b>only when no</b>
 * {@code EntityScanPackages} bean exists, so declaring one makes the application's own entities
 * disappear.
 *
 * <p>This registrar therefore registers the library package <b>and</b>, when the application had
 * not declared its own {@code @EntityScan}, the auto-configuration packages that were about to be
 * used. Both sets end up scanned and nothing is lost.
 */
public class SpringAuthEntityScanRegistrar implements ImportBeanDefinitionRegistrar, BeanFactoryAware {

    private static final String LIBRARY_ENTITY_PACKAGE = "io.github.springauth.jpa.entity";

    /** Bean name Spring Boot uses for {@link EntityScanPackages}. */
    private static final String ENTITY_SCAN_PACKAGES_BEAN =
            "org.springframework.boot.persistence.autoconfigure.EntityScanPackages";

    private BeanFactory beanFactory;

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = beanFactory;
    }

    @Override
    public void registerBeanDefinitions(AnnotationMetadata metadata, BeanDefinitionRegistry registry) {
        List<String> packages = new ArrayList<>();
        packages.add(LIBRARY_ENTITY_PACKAGE);

        boolean applicationDeclaredItsOwn = registry.containsBeanDefinition(ENTITY_SCAN_PACKAGES_BEAN);
        if (!applicationDeclaredItsOwn && AutoConfigurationPackages.has(beanFactory)) {
            // Preserve the default scan that our own registration would otherwise suppress.
            packages.addAll(AutoConfigurationPackages.get(beanFactory));
        }
        EntityScanPackages.register(registry, packages);
    }
}
