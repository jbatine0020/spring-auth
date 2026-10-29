package io.github.springauth.core.identity;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** A user explicitly authorized to access the consuming application. */
public record ApplicationUser(UUID id, String login, String email, String phoneNumber, String displayName,
                              String nom, String prenom, String externalSubject, String direction, String title,
                              UserStatus status, MfaMethod mfaMethod,
                              Set<String> roleCodes, Instant createdAt, Instant updatedAt) {
    public ApplicationUser {
        roleCodes = roleCodes == null ? Set.of() : Set.copyOf(roleCodes);
    }

    /** Compatibility constructor for existing adapters and tests using the persisted JSON value. */
    public ApplicationUser(UUID id, String login, String email, String phoneNumber, String displayName,
                           String externalSubject, String status, String mfaMethod,
                           Set<String> roleCodes, Instant createdAt, Instant updatedAt) {
        this(id, login, email, phoneNumber, displayName, null, null, externalSubject, null, null, UserStatus.parse(status),
                MfaMethod.parse(mfaMethod), roleCodes, createdAt, updatedAt);
    }

    public ApplicationUser(UUID id, String login, String email, String phoneNumber, String displayName,
                           String externalSubject, String direction, String title, String status,
                           String mfaMethod, Set<String> roleCodes, Instant createdAt, Instant updatedAt) {
        this(id, login, email, phoneNumber, displayName, null, null, externalSubject, direction, title,
                UserStatus.parse(status), MfaMethod.parse(mfaMethod), roleCodes, createdAt, updatedAt);
    }

    public ApplicationUser(UUID id, String login, String email, String phoneNumber, String displayName,
                           String nom, String prenom, String externalSubject, String direction, String title,
                           String status, String mfaMethod, Set<String> roleCodes, Instant createdAt, Instant updatedAt) {
        this(id, login, email, phoneNumber, displayName, nom, prenom, externalSubject, direction, title,
                UserStatus.parse(status), MfaMethod.parse(mfaMethod), roleCodes, createdAt, updatedAt);
    }

    public boolean canAttemptLogin() {
        return status == UserStatus.ACTIVE || status == UserStatus.PENDING_MFA;
    }
    public ApplicationUser updateAccess(String status,String mfaMethod,Set<String> roles,Instant now) {
        return new ApplicationUser(id,login,email,phoneNumber,displayName,nom,prenom,externalSubject,direction,title,
                UserStatus.parse(status), MfaMethod.parse(mfaMethod), roles, createdAt, now);
    }
    public ApplicationUser updateAccess(String status, MfaMethod mfaMethod, Set<String> roles, Instant now) {
        return new ApplicationUser(id, login, email, phoneNumber, displayName, nom, prenom, externalSubject,direction,title,
                UserStatus.parse(status),
                mfaMethod, roles, createdAt, now);
    }

    public ApplicationUser updateDirectoryAttributes(String direction, String title, Instant now) {
        return new ApplicationUser(id, login, email, phoneNumber, displayName, nom, prenom, externalSubject,
                direction, title, status, mfaMethod, roleCodes, createdAt, now);
    }

    public ApplicationUser updateDirectoryData(String email, String phoneNumber, String displayName,
                                               String direction, String title, Instant now) {
        return new ApplicationUser(id, login, email, phoneNumber, displayName, nom, prenom, externalSubject,
                direction, title, status, mfaMethod, roleCodes, createdAt, now);
    }

    public ApplicationUser updateDirectoryData(String nom, String prenom, String email, String phoneNumber,
                                               String displayName, String direction, String title, Instant now) {
        return new ApplicationUser(id, login, email, phoneNumber, displayName, nom, prenom, externalSubject,
                direction, title, status, mfaMethod, roleCodes, createdAt, now);
    }
}
