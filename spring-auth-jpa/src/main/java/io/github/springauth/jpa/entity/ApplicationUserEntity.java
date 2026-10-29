package io.github.springauth.jpa.entity;

import io.github.springauth.core.identity.ApplicationUser;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "auth_users")
public class ApplicationUserEntity {
    @Id private UUID id;
    @Column(nullable=false, unique=true, length=320) private String login;
    @Column(unique=true, length=320) private String email;
    @Column(name="phone_number", length=32) private String phoneNumber;
    @Column(name="display_name", length=256) private String displayName;
    @Column(name="last_name", length=256) private String nom;
    @Column(name="first_name", length=256) private String prenom;
    @Column(name="external_subject", nullable=false, unique=true, length=256) private String externalSubject;
    @Column(length=256) private String direction;
    @Column(name="job_title", length=256) private String title;
    @Column(nullable=false, length=32) private String status;
    @Column(name="mfa_method", nullable=false, length=20) private String mfaMethod;
    @ElementCollection(fetch=FetchType.EAGER)
    @CollectionTable(name="auth_user_roles", joinColumns=@JoinColumn(name="user_id"))
    @Column(name="role_code", nullable=false, length=64)
    private Set<String> roleCodes = new HashSet<>();
    @Column(name="created_at", nullable=false) private Instant createdAt;
    @Column(name="updated_at", nullable=false) private Instant updatedAt;
    protected ApplicationUserEntity() {}
    public static ApplicationUserEntity from(ApplicationUser u) { var e=new ApplicationUserEntity(); e.apply(u); return e; }
    public void apply(ApplicationUser u) { id=u.id(); login=u.login(); email=u.email(); phoneNumber=u.phoneNumber(); displayName=u.displayName(); nom=u.nom(); prenom=u.prenom(); externalSubject=u.externalSubject(); direction=u.direction(); title=u.title(); status=u.status().name(); mfaMethod=u.mfaMethod().name(); roleCodes.clear(); roleCodes.addAll(u.roleCodes()); createdAt=u.createdAt(); updatedAt=u.updatedAt(); }
    public ApplicationUser domain() { return new ApplicationUser(id,login,email,phoneNumber,displayName,nom,prenom,externalSubject,direction,title,io.github.springauth.core.identity.UserStatus.parse(status),io.github.springauth.core.identity.MfaMethod.parse(mfaMethod),roleCodes,createdAt,updatedAt); }
}
