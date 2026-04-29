package com.example.security.customprovider.service;

import com.example.security.customprovider.controller.ResourceController.ResourceResponse;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class ResourceService {

    public List<ResourceResponse> listResources() {
        return List.of(
                new ResourceResponse(1L, "Resource Alpha", "Accessible by all authenticated users"),
                new ResourceResponse(2L, "Resource Beta", "Accessible by all authenticated users")
        );
    }

    public Map<String, Object> getAdminResource(String username) {
        return Map.of(
                "message", "Admin-only resource",
                "accessedBy", username
        );
    }
}
