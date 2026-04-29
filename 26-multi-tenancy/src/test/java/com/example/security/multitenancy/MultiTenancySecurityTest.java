package com.example.security.multitenancy;

import com.example.security.multitenancy.filter.TenantResolutionFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class MultiTenancySecurityTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // Tenant header validation
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Missing X-Tenant-ID header")
    class MissingTenantHeader {

        @Test
        @DisplayName("request without X-Tenant-ID returns 400")
        void missingTenantHeaderReturns400() throws Exception {
            mockMvc.perform(get("/api/data"))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("request with blank X-Tenant-ID returns 400")
        void blankTenantHeaderReturns400() throws Exception {
            mockMvc.perform(get("/api/data")
                            .header(TenantResolutionFilter.TENANT_HEADER, "   "))
                    .andExpect(status().isBadRequest());
        }
    }

    // -------------------------------------------------------------------------
    // Tenant A access
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Tenant A access")
    class TenantAAccess {

        @Test
        @DisplayName("tenant-a user can access /api/data — 200")
        void tenantAUserCanAccessData() throws Exception {
            mockMvc.perform(get("/api/data")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-a")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("tenant-a admin can access /api/data — 200")
        void tenantAAdminCanAccessData() throws Exception {
            mockMvc.perform(get("/api/data")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-a")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("tenant-a user can access /api/tenant/info — 200")
        void tenantAUserCanAccessTenantInfo() throws Exception {
            mockMvc.perform(get("/api/tenant/info")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-a")
                            .with(user("user").roles("USER")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tenantId").value("tenant-a"))
                    .andExpect(jsonPath("$.username").value("user"));
        }

        @Test
        @DisplayName("unauthenticated request to tenant-a returns 401")
        void unauthenticatedTenantAReturns401() throws Exception {
            mockMvc.perform(get("/api/data")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-a"))
                    .andExpect(status().isUnauthorized());
        }
    }

    // -------------------------------------------------------------------------
    // Tenant B access
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Tenant B access")
    class TenantBAccess {

        @Test
        @DisplayName("tenant-b user bob can access /api/data — 200")
        void tenantBBobCanAccessData() throws Exception {
            mockMvc.perform(get("/api/data")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-b")
                            .with(user("bob").roles("USER")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("tenant-b admin can access /api/tenant/info — 200")
        void tenantBAdminCanAccessTenantInfo() throws Exception {
            mockMvc.perform(get("/api/tenant/info")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-b")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tenantId").value("tenant-b"));
        }
    }

    // -------------------------------------------------------------------------
    // POST /api/data
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("POST /api/data")
    class CreateData {

        @Test
        @DisplayName("authenticated user can create data in their tenant — 201")
        void authenticatedUserCanCreateData() throws Exception {
            mockMvc.perform(post("/api/data")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-a")
                            .with(user("user").roles("USER"))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"content\":\"new record\"}"))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.tenantId").value("tenant-a"))
                    .andExpect(jsonPath("$.content").value("new record"));
        }

        @Test
        @DisplayName("unauthenticated POST returns 401")
        void unauthenticatedPostReturns401() throws Exception {
            mockMvc.perform(post("/api/data")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"content\":\"new record\"}"))
                    .andExpect(status().isUnauthorized());
        }
    }

    // -------------------------------------------------------------------------
    // Tenant isolation — data scoping
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Tenant data isolation")
    class TenantDataIsolation {

        @Test
        @DisplayName("tenant-a data response contains only tenant-a records")
        void tenantADataContainsOnlyTenantARecords() throws Exception {
            mockMvc.perform(get("/api/data")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-a")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].tenantId").value("tenant-a"));
        }

        @Test
        @DisplayName("tenant-b data response contains only tenant-b records")
        void tenantBDataContainsOnlyTenantBRecords() throws Exception {
            mockMvc.perform(get("/api/data")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-b")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].tenantId").value("tenant-b"));
        }
    }

    // -------------------------------------------------------------------------
    // Same username in different tenants are independent identities
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Same username across tenants")
    class SameUsernameAcrossTenants {

        @Test
        @DisplayName("'admin' in tenant-a and 'admin' in tenant-b are independent — both return tenant-specific info")
        void adminInTenantAAndTenantBAreIndependent() throws Exception {
            // admin in tenant-a
            mockMvc.perform(get("/api/tenant/info")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-a")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tenantId").value("tenant-a"))
                    .andExpect(jsonPath("$.username").value("admin"));

            // admin in tenant-b
            mockMvc.perform(get("/api/tenant/info")
                            .header(TenantResolutionFilter.TENANT_HEADER, "tenant-b")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tenantId").value("tenant-b"))
                    .andExpect(jsonPath("$.username").value("admin"));
        }
    }
}
