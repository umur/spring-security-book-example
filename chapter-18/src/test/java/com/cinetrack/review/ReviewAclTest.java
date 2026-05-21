package com.cinetrack.review;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP-layer ACL tests for the review resource.
 *
 * Uses {@code MockMvcBuilders.webAppContextSetup} with {@code springSecurity()}
 * so the real security filter chain: including method security AOP and the ACL
 * JDBC infrastructure: is exercised on every request.
 *
 * The ACL tables are truncated before each test so tests are fully independent
 * without needing to restart the Spring context between runs.
 */
@SpringBootTest
@ActiveProfiles("test")
@TestPropertySource(properties = {
    // Separate DB so this test class does not share H2 state with AclSecurityTest.
    "spring.datasource.url=jdbc:h2:mem:cinetrack-review-acl-test;DB_CLOSE_DELAY=-1;MODE=MySQL"
})
class ReviewAclTest {

    @Autowired
    private WebApplicationContext wac;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JdbcTemplate jdbc;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(wac)
                .apply(springSecurity())
                .build();

        // Truncate in FK-safe order so each test starts with empty ACL + review tables.
        jdbc.execute("DELETE FROM acl_entry");
        jdbc.execute("DELETE FROM acl_object_identity");
        jdbc.execute("DELETE FROM acl_sid");
        jdbc.execute("DELETE FROM acl_class");
        jdbc.execute("DELETE FROM reviews");
    }

    // ── owner can delete their own review ─────────────────────────────────────

    @Test
    void reviewOwner_canDelete_ownReview() throws Exception {
        Long id = createReview("alice", "password", 10L, "Great film!");

        // alice holds the DELETE ACL entry on her own review
        mockMvc.perform(delete("/api/reviews/" + id)
                        .with(httpBasic("alice", "password")))
                .andExpect(status().isNoContent());
    }

    // ── non-owner cannot delete ───────────────────────────────────────────────

    @Test
    void otherUser_cannotDelete_review() throws Exception {
        Long id = createReview("alice", "password", 11L, "My review");

        // bob has no DELETE ACL entry on alice's review → 403
        mockMvc.perform(delete("/api/reviews/" + id)
                        .with(httpBasic("bob", "password")))
                .andExpect(status().isForbidden());
    }

    // ── any ROLE_USER can read a review they did not create ───────────────────

    @Test
    void anyUser_canRead_review() throws Exception {
        // alice (ROLE_USER via user() post-processor) creates the review;
        // the service grants READ to the owner and to GrantedAuthoritySid("ROLE_USER")
        Long id = createReviewAsUser("alice", 12L, "Worth watching");

        // bob (ROLE_USER) reads it: 200 because of the ROLE_USER ACE
        mockMvc.perform(get("/api/reviews/" + id)
                        .with(user("bob").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").value("Worth watching"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /** Creates a review via HTTP Basic and returns the new review's id. */
    private Long createReview(String username, String password,
                               Long movieId, String content) throws Exception {
        String body = objectMapper.writeValueAsString(
                new ReviewController.ReviewRequest(movieId, content));

        MvcResult result = mockMvc.perform(post("/api/reviews")
                        .with(httpBasic(username, password))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        Long id = objectMapper.readTree(responseBody).get("id").asLong();
        assertThat(id).isPositive();
        return id;
    }

    /** Creates a review as a mock user with ROLE_USER (bypasses password check). */
    private Long createReviewAsUser(String username, Long movieId, String content) throws Exception {
        String body = objectMapper.writeValueAsString(
                new ReviewController.ReviewRequest(movieId, content));

        MvcResult result = mockMvc.perform(post("/api/reviews")
                        .with(user(username).roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        Long id = objectMapper.readTree(responseBody).get("id").asLong();
        assertThat(id).isPositive();
        return id;
    }
}
