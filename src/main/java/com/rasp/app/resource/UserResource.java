package com.rasp.app.resource;

import java.util.Map;

public class UserResource {
    private Map<String,Object> authMap;
   private Map<String,Object> resourceMap;
   private String resourceName;

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public Map<String, Object> getAuthMap() {
        return authMap;
    }

    public void setAuthMap(Map<String, Object> authMap) {
        this.authMap = authMap;
    }

    public Map<String, Object> getResourceMap() {
        return resourceMap;
    }

    public void setResourceMap(Map<String, Object> resourceMap) {
        this.resourceMap = resourceMap;
    }
}
