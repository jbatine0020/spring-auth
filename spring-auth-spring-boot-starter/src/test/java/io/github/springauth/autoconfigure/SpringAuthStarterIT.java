package io.github.springauth.autoconfigure;

import io.github.springauth.core.crypto.SecretCipher;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.service.LoginResult;
import io.github.springauth.core.service.LoginService;
import io.github.springauth.core.service.MfaService;
import io.github.springauth.core.service.PasswordService;
import io.github.springauth.core.service.RoleService;
import io.github.springauth.core.service.SessionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Proves the starter actually boots and works end to end.
 *
 * <p>Compilation says nothing about a Spring auto-configuration: the failure modes that matter are
 * a missing bean, an entity the persistence unit never scanned, a filter registered in the wrong
 * order. All of those only surface when a real context starts and serves a request, which is what
 * this test does, against H2, with the whole graph wired by the starter alone.
 */
@SpringBootTest(classes = TestApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
class SpringAuthStarterIT {

    private static final String LOGIN = "alex@example.com";
    private static final String PASSWORD = "Correct-Horse-42!";
    private static final AuthUserId USER_ID =
            AuthUserId.of("11111111-1111-1111-1111-111111111111");

    /**
     * A fresh master key per run, rather than a committed one.
     *
     * <p>Keeps a value that is indistinguishable from a real secret out of the repository, and
     * removes any chance of someone lifting a "test" key into a deployment.
     */
    @DynamicPropertySource
    static void cryptoKey(DynamicPropertyRegistry registry) {
        registry.add("spring-auth.crypto.master-key", SecretCipher::generateMasterKey);
    }

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private LoginService loginService;

    @Autowired
    private PasswordService passwordService;

    @Autowired
    private SessionService sessionService;

    @Autowired
    private MfaService mfaService;

    @Autowired
    private RoleService roleService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        // springSecurity() installs the library's filter chain. Without it the requests bypass
        // security entirely and the test would prove nothing about what an anonymous caller can
        // actually reach.
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
        passwordService.setPassword(USER_ID, PASSWORD, false);
    }

    @Test
    @DisplayName("the context wires every service")
    void contextLoads() {
        assertThat(loginService).isNotNull();
        assertThat(passwordService).isNotNull();
        assertThat(sessionService).isNotNull();
        assertThat(mfaService).isNotNull();
        assertThat(roleService).isNotNull();
    }

    @Test
    @DisplayName("the JPA entities are mapped and reachable")
    void jpaMappingWorks() {
        // setUp already wrote credentials and a history entry through the JPA adapters; reading
        // the login back proves both the entity scan and the mapping.
        LoginResult result = loginService.login(LOGIN, PASSWORD,
                io.github.springauth.core.model.RequestContext.empty());

        assertThat(result.status()).isEqualTo(LoginResult.Status.AUTHENTICATED);
        assertThat(result.tokens().accessToken()).isNotBlank();
    }

    @Test
    @DisplayName("roles persist and expand into token permissions")
    void rolesResolveIntoPermissions() {
        roleService.seedSystemRole("ADMIN", "Administrator", null,
                java.util.Set.of("orders:read", "orders:write"));

        assertThat(roleService.get("ADMIN").getPermissions())
                .containsExactlyInAnyOrder("orders:read", "orders:write");
    }

    @Test
    @DisplayName("POST /login answers over HTTP without authentication")
    void loginEndpointIsPublicAndWorks() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"" + LOGIN + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.tokens.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokens.refreshToken").isNotEmpty());
    }

    @Test
    @DisplayName("a wrong password answers 401 with the generic code")
    void loginEndpointRejectsBadCredentials() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"" + LOGIN + "\",\"password\":\"wrong-password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("LOGIN_INVALID"));
    }

    @Test
    @DisplayName("an unknown login answers exactly like a wrong password")
    void loginEndpointDoesNotLeakAccountExistence() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"ghost@example.com\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("LOGIN_INVALID"));
    }

    @Test
    @DisplayName("a missing field answers 400 with field-level detail")
    void loginEndpointValidatesItsPayload() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"\",\"password\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.details").isNotEmpty());
    }

    @Test
    @DisplayName("a protected endpoint refuses an anonymous caller")
    void protectedEndpointRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me/login-history"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("the JWKS is published and exposes public material only")
    void jwksIsPublished() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                // "d" is the private exponent: its presence would mean the signing key just leaked.
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    @Test
    @DisplayName("the whole refresh cycle works over HTTP")
    void refreshCycleWorks() throws Exception {
        String body = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"" + LOGIN + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String refreshToken = extract(body, "refreshToken");

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());

        // Presenting the rotated token again is a replay: the family is burnt.
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_TOKEN_REPLAY"));
    }

    @Test
    @DisplayName("the forgotten-password endpoint never reveals whether the account exists")
    void passwordResetRequestIsAlwaysAccepted() throws Exception {
        mockMvc.perform(post("/api/v1/auth/password-reset:request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"ghost@example.com\"}"))
                .andExpect(status().isAccepted());

        mockMvc.perform(post("/api/v1/auth/password-reset:request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"login\":\"" + LOGIN + "\"}"))
                .andExpect(status().isAccepted());
    }

    private static String extract(String json, String field) {
        int start = json.indexOf("\"" + field + "\":\"") + field.length() + 4;
        return json.substring(start, json.indexOf('"', start));
    }
}
