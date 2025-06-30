//package com.example.demo.config;
//
//import org.springframework.cache.CacheManager;
//import org.springframework.cache.annotation.EnableCaching;
//import org.springframework.cache.caffeine.CaffeineCacheManager;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import com.github.benmanes.caffeine.cache.Caffeine;
//
//import java.time.Duration;
//
//@Configuration
//@EnableCaching
//public class CacheConfig {
//    @Bean
//    public CacheManager cacheManager() {
//        CaffeineCacheManager cacheManager = new CaffeineCacheManager("roleResourceCache");
//        cacheManager.setCaffeine(caffeineCacheBuilder());
//        return cacheManager;
//    }
//
//    Caffeine<Object, Object> caffeineCacheBuilder() {
//        return Caffeine.newBuilder()
//                .initialCapacity(100)
//                .maximumSize(500)
//                .expireAfterWrite(Duration.ofMinutes(10));
//    }
//}
