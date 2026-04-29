package com.example.security.multitenancy.security;

/**
 * Thread-local holder for the current tenant ID.
 * Set early in the request lifecycle by {@link TenantResolutionFilter}
 * and cleared after the response is committed.
 */
public final class TenantContext {

    private static final ThreadLocal<String> CURRENT_TENANT = new ThreadLocal<>();

    private TenantContext() {}

    public static void setTenantId(String tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    public static String getTenantId() {
        return CURRENT_TENANT.get();
    }

    public static void clear() {
        CURRENT_TENANT.remove();
    }
}
