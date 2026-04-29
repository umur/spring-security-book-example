package com.example.security.microservice;

import com.example.security.microservice.dto.AggregatedResponse;
import com.example.security.microservice.service.DataService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class MicroserviceSecurityTest {

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    DataService dataService;

    // -----------------------------------------------------------------------
    // /api/internal/data — resource server endpoint (JWT validation)
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("GET /api/internal/data — resource server JWT validation")
    class InternalDataEndpoint {

        @Test
        @DisplayName("returns 401 when no token is provided")
        void returns401WithoutToken() throws Exception {
            mockMvc.perform(get("/api/internal/data"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("returns 401 when an invalid/malformed token is provided")
        void returns401WithInvalidToken() throws Exception {
            mockMvc.perform(get("/api/internal/data")
                            .header("Authorization", "Bearer not-a-valid-jwt"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("returns 200 when a valid service JWT is provided")
        void returns200WithValidServiceJwt() throws Exception {
            when(dataService.getInternalData(org.mockito.ArgumentMatchers.any()))
                    .thenReturn(new com.example.security.microservice.dto.InternalDataResponse(
                            "microservice-security-example",
                            "ok",
                            List.of("record-001", "record-002", "record-003"),
                            Instant.now()
                    ));

            mockMvc.perform(get("/api/internal/data")
                            .with(jwt()
                                    .jwt(j -> j.subject("service-account-001")
                                            .claim("scope", "internal.read"))
                                    .authorities(
                                            new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_internal.read")
                                    )))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.serviceId").value("microservice-security-example"))
                    .andExpect(jsonPath("$.status").value("ok"))
                    .andExpect(jsonPath("$.records").isArray());
        }

        @Test
        @DisplayName("returns 200 for any authenticated service principal regardless of scope")
        void returns200ForAuthenticatedPrincipal() throws Exception {
            when(dataService.getInternalData(org.mockito.ArgumentMatchers.any()))
                    .thenReturn(new com.example.security.microservice.dto.InternalDataResponse(
                            "microservice-security-example",
                            "ok",
                            List.of("record-001"),
                            Instant.now()
                    ));

            mockMvc.perform(get("/api/internal/data")
                            .with(jwt()
                                    .jwt(j -> j.subject("another-service"))
                                    .authorities(
                                            new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_other.scope")
                                    )))
                    .andExpect(status().isOk());
        }
    }

    // -----------------------------------------------------------------------
    // /api/aggregated — OAuth2 client endpoint
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("GET /api/aggregated — OAuth2 client credentials aggregator")
    class AggregatedEndpoint {

        @Test
        @DisplayName("returns 401 when no token is provided")
        void returns401WithoutToken() throws Exception {
            mockMvc.perform(get("/api/aggregated"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("returns 200 and aggregated payload when a valid JWT is provided")
        void returns200WithValidJwt() throws Exception {
            AggregatedResponse mockResponse = new AggregatedResponse(
                    "microservice-security-example",
                    List.of("local-001", "local-002"),
                    new AggregatedResponse.ExternalData("external-service", List.of("ext-item-1")),
                    Instant.now()
            );
            when(dataService.getAggregatedData()).thenReturn(mockResponse);

            mockMvc.perform(get("/api/aggregated")
                            .with(jwt()
                                    .jwt(j -> j.subject("api-gateway"))
                                    .authorities(
                                            new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_internal.read")
                                    )))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.aggregatorServiceId").value("microservice-security-example"))
                    .andExpect(jsonPath("$.localRecords").isArray())
                    .andExpect(jsonPath("$.externalData.sourceService").value("external-service"))
                    .andExpect(jsonPath("$.externalData.items").isArray());
        }
    }
}
