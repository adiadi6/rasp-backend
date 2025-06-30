//package com.example.demo.config;
//
//import com.ibm.icu.impl.coll.Collation;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.cache.Cache;
//import org.springframework.cache.CacheManager;
//import org.springframework.stereotype.Component;
//import platform.resource.BaseResource;
//
//import javax.annotation.PostConstruct;
//import java.util.Collection;
//import java.util.Collections;
//
//@Component
//public class Init {
//
//    @Autowired
//    CacheManager cacheManager;
//
//    @PostConstruct
//    public void preloadCache() {
//        System.out.println("Preloading data into cache..." + this);
//
//        RoleResourceAccess roleResourceAccess= RoleResourceAccess.getInstance(cacheManager);
//        BaseResource[] baseResource=roleResourceAccess.getAcces();
//        System.out.println(baseResource);
//      Collection<String> stringCollation= cacheManager.getCacheNames();
//        Cache cache = cacheManager.getCache("roleResourceCache");
//        System.out.println("cachemanager object: " + cacheManager);
//        if (cache != null) {
//            cache.put("allUsersKey", baseResource);  // Store the list under "allUsersKey"
//        }
//
//        else{
//            System.out.println("running else in Post Con");
//        }
//    }
//}
