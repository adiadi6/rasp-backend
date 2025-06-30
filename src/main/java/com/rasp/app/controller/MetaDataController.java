package com.rasp.app.controller;


import com.rasp.app.resource.MetaDataDto;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.core.type.filter.TypeFilter;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import platform.util.ApplicationException;

import java.lang.reflect.Method;
import java.util.*;
@CrossOrigin("*")
@RestController
public class MetaDataController {

    @GetMapping("/api/getAllResourceMetaData")
    public ResponseEntity<?> getAllMetaData() {
        List<MetaDataDto> dtos = processMetadata();
        return ResponseEntity.ok(dtos);
    }

    @GetMapping("/api/GetAllResource")
    public ResponseEntity<?> getAllResource() throws ApplicationException {
        List<String> resources = getAllResources();
        return ResponseEntity.ok(resources);
    }

    @GetMapping("/api/getAllResourceMetaData/{resource}")
    public ResponseEntity<?> getMetaData(@PathVariable String resource) {
        List<MetaDataDto> dtos = processMetadata(resource);
        return ResponseEntity.ok(dtos);
    }


    public static List<MetaDataDto> processMetadata() {
        List<MetaDataDto> dtos = new ArrayList<>();
        try {
            ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);  // 'false' to disable default filters

            // Add a filter to look for classes annotated with @Component
            TypeFilter filter = new AnnotationTypeFilter(Component.class);
            provider.addIncludeFilter(filter);

            // Scan the base package (use package name, not the full path)
            String basePackage = "com.flightBooking.resource";  // Just the package name

            Map<String, Object> values = new HashMap<>();
            if (basePackage != null) {
                Set<BeanDefinition> components = provider.findCandidateComponents(basePackage);

                for (BeanDefinition component : components) {

                    String fullClassName = component.getBeanClassName();

                    // Extract the class name (e.g., Airline, Bookings) from the full class name
                    String simpleClassName = fullClassName.substring(fullClassName.lastIndexOf('.') + 1);


                    Class<?> clazz = Class.forName(String.valueOf(fullClassName));
                    Object instance = clazz.getDeclaredConstructor().newInstance();

                    // Access the getMetaData() method
                    Method getMetaDataMethod = clazz.getMethod("getMetaData");
                    Object metaData = getMetaDataMethod.invoke(instance);

                    // Access the getFieldsArray() method from metaData
                    Method getFieldsArrayMethod = metaData.getClass().getMethod("getFieldsArray");
                    Object[] fieldsArray = (Object[]) getFieldsArrayMethod.invoke(metaData);
                    //  System.out.println(fieldsArray);


                    List<Map<String, Object>> fieldsData = new ArrayList<>();


                    for (Object field : fieldsArray) {
                        Map<String, Object> fieldValues = new HashMap<>();
                        // Assuming `field` has methods `isRequired`, `getType`, and `getName`
                        //      System.out.println( field.getClass().getName());
                        java.lang.reflect.Field field1 = field.getClass().getDeclaredField("name");
                        String n = field1.getName();
                        java.lang.reflect.Field field2 = field.getClass().getDeclaredField("required");
                        String required = field2.getName();
                        java.lang.reflect.Field field3 = field.getClass().getDeclaredField("type");
                        String type = field3.getName();
                        java.lang.reflect.Field field4 = field.getClass().getDeclaredField("foreign");
                        String f = field4.getName();

                        java.lang.reflect.Field field5 = field.getClass().getDeclaredField("possible_value");
                        String p = field5.getName();

                        Method isRequiredMethod = field.getClass().getMethod("isRequired");
                        boolean isRequired = (boolean) isRequiredMethod.invoke(field);
                        fieldValues.put(required, isRequired);


                        Method getTypeMethod = field.getClass().getMethod("getType");
                        String fieldType = (String) getTypeMethod.invoke(field);
                        fieldValues.put(type, fieldType);


                        Method getNameMethod = field.getClass().getMethod("getName");
                        String fieldName = (String) getNameMethod.invoke(field);
                        fieldValues.put(n, fieldName);

                        Method getForeignMethod = field.getClass().getMethod("getForeign");
                        Object foreign = getForeignMethod.invoke(field);


                        if (foreign != null) {
                            String foreignClass = (String) foreign.getClass().getMethod("getResource").invoke(foreign);
                            fieldValues.put(f, foreignClass);

                            fieldValues.put("foreign_field", "id");
                        }
                        Method getPossibleValueMethod = field.getClass().getMethod("getPossible_value");
                        Object posible_value = getPossibleValueMethod.invoke(field);
                        if (posible_value != null) {
                            fieldValues.put(p, posible_value);
                            fieldValues.put("isEnum",true);
                        }



                        fieldsData.add(fieldValues);

                    }



                    MetaDataDto dto = new MetaDataDto();
                    dto.setResource(simpleClassName);
                    dto.setFieldValues(fieldsData);
                    dtos.add(dto);

                }
            }


        } catch (Exception e) {
            e.printStackTrace();
            // Handle exception as needed, e.g., log it or throw a custom exception
        }

        return dtos;
    }


    private List<String> getAllResources() throws ApplicationException {
        ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);  // 'false' to disable default filters

        // Add a filter to look for classes annotated with @Component
        TypeFilter filter = new AnnotationTypeFilter(Component.class);
        provider.addIncludeFilter(filter);

        // Scan the base package (use package name, not the full path)
        String basePackage = "com.flightBooking.resource";  // Just the package name
        Set<BeanDefinition> components = provider.findCandidateComponents(basePackage);
        List<String> resources = new ArrayList<>();
        // Print the class names found
        for (BeanDefinition component : components) {
            String fullClassName = component.getBeanClassName();

            // Extract the class name (e.g., Airline, Bookings) from the full class name
            String simpleClassName = fullClassName.substring(fullClassName.lastIndexOf('.') + 1);
            resources.add(simpleClassName);

        }


        return resources;
    }

    public static List<MetaDataDto> processMetadata(String resource) {


        List<MetaDataDto> dtos = new ArrayList<>();
        try {

            ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);  // 'false' to disable default filters

            // Add a filter to look for classes annotated with @Component
            TypeFilter filter = new AnnotationTypeFilter(Component.class);
            provider.addIncludeFilter(filter);
           String fileName;
            // Scan the base package (use package name, not the full path)
            String basePackage = "com.example.demo";  // Just the package name

            Map<String, Object> values = new HashMap<>();
            if (basePackage != null) {
                Set<BeanDefinition> components = provider.findCandidateComponents(basePackage);

                for (BeanDefinition component : components) {

                    String fullClassName = component.getBeanClassName();

                    // Extract the class name (e.g., Airline, Bookings) from the full class name
                    String simpleClassName = fullClassName.substring(fullClassName.lastIndexOf('.') + 1);
                 fileName=simpleClassName;

                    if (!resource.equalsIgnoreCase(simpleClassName)) {
                        continue;
                    }
                        //values.put("resource",fileName);



                        Class<?> clazz = Class.forName(String.valueOf(fullClassName));
                        Object instance = clazz.getDeclaredConstructor().newInstance();

                        // Access the getMetaData() method
                        Method getMetaDataMethod = clazz.getMethod("getMetaData");
                        Object metaData = getMetaDataMethod.invoke(instance);

                        // Access the getFieldsArray() method from metaData
                        Method getFieldsArrayMethod = metaData.getClass().getMethod("getFieldsArray");
                        Object[] fieldsArray = (Object[]) getFieldsArrayMethod.invoke(metaData);
                        //  System.out.println(fieldsArray);


                        List<Map<String, Object>> fieldsData = new ArrayList<>();


                        for (Object field : fieldsArray) {
                            Map<String, Object> fieldValues = new HashMap<>();
                            // Assuming `field` has methods `isRequired`, `getType`, and `getName`
                            //      System.out.println( field.getClass().getName());
                            java.lang.reflect.Field field1 = field.getClass().getDeclaredField("name");
                            String n = field1.getName();
                            java.lang.reflect.Field field2 = field.getClass().getDeclaredField("required");
                            String required = field2.getName();
                            java.lang.reflect.Field field3 = field.getClass().getDeclaredField("type");
                            String type = field3.getName();
                            java.lang.reflect.Field field4 = field.getClass().getDeclaredField("foreign");
                            String f = field4.getName();
                            java.lang.reflect.Field field5 = field.getClass().getDeclaredField("possible_value");
                            String p = field5.getName();

                            Method isRequiredMethod = field.getClass().getMethod("isRequired");
                            boolean isRequired = (boolean) isRequiredMethod.invoke(field);
                            fieldValues.put(required, isRequired);


                            Method getTypeMethod = field.getClass().getMethod("getType");
                            String fieldType = (String) getTypeMethod.invoke(field);
                            fieldValues.put(type, fieldType);




                            Method getNameMethod = field.getClass().getMethod("getName");
                            String fieldName = (String) getNameMethod.invoke(field);
                            fieldValues.put(n, fieldName);

                            Method getForeignMethod = field.getClass().getMethod("getForeign");
                            Object foreign = getForeignMethod.invoke(field);
                            if (foreign != null) {
                                String foreignClass = (String) foreign.getClass().getMethod("getResource").invoke(foreign);
                                fieldValues.put(f, foreignClass);

                                fieldValues.put("foreign_field", "id");
                            }
                            Method getPossibleValueMethod = field.getClass().getMethod("getPossible_value");
                            Object posible_value = getPossibleValueMethod.invoke(field);
                            if (posible_value != null) {
                                fieldValues.put(p, posible_value);
                                fieldValues.put("isEnum",true);
                            }



                            fieldsData.add(fieldValues);

                        }
                        MetaDataDto dto = new MetaDataDto();
                        dto.setResource(fileName);
                        dto.setFieldValues(fieldsData);
                        dtos.add(dto);




                }
            }


        } catch (Exception e) {
            e.printStackTrace();
            // Handle exception as needed, e.g., log it or throw a custom exception
        }

        return dtos;
    }


//    public static List<MetaDataDto> processMetadata(String resource) {
//        List<MetaDataDto> dtos = new ArrayList<>();
//        try {
//
//
//            File folder = new File("src/main/java/com/flightBooking/resource/");
//            File[] files = folder.listFiles((dir, name) -> name.endsWith(".java"));
//            Map<String, Object> values = new HashMap<>();
//            if (files != null) {
//                for (File file : files) {
//
//                    String fileName = file.getName().replace(".java", "");
//
//                    // Skip files with "Result" suffix
//                    if (fileName.endsWith("Result")) {
//                        continue;
//                    }
//                    if (resource.equals(fileName)) {
//                        //values.put("resource",fileName);
//
//                        String className = "com.flightBooking.resource." + fileName;
//
//                        Class<?> clazz = Class.forName(className);
//                        Object instance = clazz.getDeclaredConstructor().newInstance();
//
//                        // Access the getMetaData() method
//                        Method getMetaDataMethod = clazz.getMethod("getMetaData");
//                        Object metaData = getMetaDataMethod.invoke(instance);
//
//                        // Access the getFieldsArray() method from metaData
//                        Method getFieldsArrayMethod = metaData.getClass().getMethod("getFieldsArray");
//                        Object[] fieldsArray = (Object[]) getFieldsArrayMethod.invoke(metaData);
//                        //  System.out.println(fieldsArray);
//
//
//                        List<Map<String, Object>> fieldsData = new ArrayList<>();
//
//
//                        for (Object field : fieldsArray) {
//                            Map<String, Object> fieldValues = new HashMap<>();
//                            // Assuming `field` has methods `isRequired`, `getType`, and `getName`
//                            //      System.out.println( field.getClass().getName());
//                            java.lang.reflect.Field field1 = field.getClass().getDeclaredField("name");
//                            String n = field1.getName();
//                            java.lang.reflect.Field field2 = field.getClass().getDeclaredField("required");
//                            String required = field2.getName();
//                            java.lang.reflect.Field field3 = field.getClass().getDeclaredField("type");
//                            String type = field3.getName();
//                            java.lang.reflect.Field field4 = field.getClass().getDeclaredField("foreign");
//                            String f = field4.getName();
//
//                            Method isRequiredMethod = field.getClass().getMethod("isRequired");
//                            boolean isRequired = (boolean) isRequiredMethod.invoke(field);
//                            fieldValues.put(required, isRequired);
//
//
//                            Method getTypeMethod = field.getClass().getMethod("getType");
//                            String fieldType = (String) getTypeMethod.invoke(field);
//                            fieldValues.put(type, fieldType);
//
//
//                            Method getNameMethod = field.getClass().getMethod("getName");
//                            String fieldName = (String) getNameMethod.invoke(field);
//                            fieldValues.put(n, fieldName);
//
//                            Method getForeignMethod = field.getClass().getMethod("getForeign");
//                            Object foreign = getForeignMethod.invoke(field);
//                            if (foreign != null) {
//                                String foreignClass = (String) foreign.getClass().getMethod("getResource").invoke(foreign);
//                                Class<?> claz = Class.forName(foreignClass);
//                                Object instance1 = clazz.getDeclaredConstructor().newInstance();
//                                fieldValues.put(f, foreignClass);
//                                fieldValues.put("foreign_field", "id");
//                            }
//
//                            fieldsData.add(fieldValues);
//
//                        }
//
//                        //  values.put("filds",fieldsData);
//
////                    for (Map.Entry<String, Object> entry : values.entrySet()) {
////                        String key = entry.getKey();
////                        Object value = entry.getValue();
////
////                        // Print or process the key-value pairs
////                        System.out.println("Key: " + key + ", Value: " + value);
////                    }
//                        MetaDataDto dto = new MetaDataDto();
//                        dto.setResource(fileName);
//                        dto.setFieldValues(fieldsData);
//                        dtos.add(dto);
//
//                    }
//                }
//            }
//
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            // Handle exception as needed, e.g., log it or throw a custom exception
//        }
//
//        return dtos;
//    }
    //    private List<String> getAllResources() throws ApplicationException {
//        File folder = new File("src/main/java/com/flightBooking/resource/");
//        File[] files = folder.listFiles((dir, name) -> name.endsWith(".java"));
//        Map<String, Object> values = new HashMap<>();
//        List<String> resources = new ArrayList<>();
//        if (files != null) {
//            for (File file : files) {
//                String fileName = file.getName().replace(".java", "");
//
//                // Skip files with "Result" suffix
//                if (fileName.endsWith("Result")) {
//                    continue;
//                }
//                resources.add(fileName);
//            }
//        } else {
//            throw new ApplicationException(ExceptionSeverity.ERROR, "Files is empty");
//        }
//
//        return resources;
//    }


//    public static List<MetaDataDto> processMetadata() {
//        List<MetaDataDto> dtos = new ArrayList<>();
//        try {
//
//            System.out.println("Reaching Try ");
//            File folder = new File("src/main/java/com/flightBooking/resource/");
//            File[] files = folder.listFiles((dir, name) -> name.endsWith(".java"));
//            Map<String, Object> values = new HashMap<>();
//            if (files != null) {
//                System.out.println("Reaching IF ");
//                for (File file : files) {
//                    System.out.println("Reaching FOR ");
//                    String fileName = file.getName().replace(".java", "");
//
//                    // Skip files with "Result" suffix
//                    if (fileName.endsWith("Result")) {
//                        continue;
//                    }
//                    //values.put("resource",fileName);
//
//                    String className = "com.flightBooking.resource." + fileName;
//
//                    Class<?> clazz = Class.forName(className);
//                    Object instance = clazz.getDeclaredConstructor().newInstance();
//
//                    // Access the getMetaData() method
//                    Method getMetaDataMethod = clazz.getMethod("getMetaData");
//                    Object metaData = getMetaDataMethod.invoke(instance);
//
//                    // Access the getFieldsArray() method from metaData
//                    Method getFieldsArrayMethod = metaData.getClass().getMethod("getFieldsArray");
//                    Object[] fieldsArray = (Object[]) getFieldsArrayMethod.invoke(metaData);
//                    //  System.out.println(fieldsArray);
//
//
//                    List<Map<String, Object>> fieldsData = new ArrayList<>();
//
//
//                    for (Object field : fieldsArray) {
//                        Map<String, Object> fieldValues = new HashMap<>();
//                        // Assuming `field` has methods `isRequired`, `getType`, and `getName`
//                        //      System.out.println( field.getClass().getName());
//                        java.lang.reflect.Field field1 = field.getClass().getDeclaredField("name");
//                        String n = field1.getName();
//                        java.lang.reflect.Field field2 = field.getClass().getDeclaredField("required");
//                        String required = field2.getName();
//                        java.lang.reflect.Field field3 = field.getClass().getDeclaredField("type");
//                        String type = field3.getName();
//                        java.lang.reflect.Field field4 = field.getClass().getDeclaredField("foreign");
//                        String f = field4.getName();
//
//                        Method isRequiredMethod = field.getClass().getMethod("isRequired");
//                        boolean isRequired = (boolean) isRequiredMethod.invoke(field);
//                        fieldValues.put(required, isRequired);
//
//
//                        Method getTypeMethod = field.getClass().getMethod("getType");
//                        String fieldType = (String) getTypeMethod.invoke(field);
//                        fieldValues.put(type, fieldType);
//
//
//                        Method getNameMethod = field.getClass().getMethod("getName");
//                        String fieldName = (String) getNameMethod.invoke(field);
//                        fieldValues.put(n, fieldName);
//
//                        Method getForeignMethod = field.getClass().getMethod("getForeign");
//                        Object foreign = getForeignMethod.invoke(field);
//                        if (foreign != null) {
//                            String foreignClass = (String) foreign.getClass().getMethod("getResource").invoke(foreign);
//                            fieldValues.put(f, foreignClass);
//
//                            fieldValues.put("foreign_field", "id");
//                        }
//
//                        fieldsData.add(fieldValues);
//
//                    }
//
//                    //  values.put("filds",fieldsData);
//
////                    for (Map.Entry<String, Object> entry : values.entrySet()) {
////                        String key = entry.getKey();
////                        Object value = entry.getValue();
////
////                        // Print or process the key-value pairs
////                        System.out.println("Key: " + key + ", Value: " + value);
////                    }
//                    MetaDataDto dto = new MetaDataDto();
//                    dto.setResource(fileName);
//                    dto.setFieldValues(fieldsData);
//                    dtos.add(dto);
//
//                }
//            } else {
//                System.out.println("Reaching ELSE ");
//                throw new ApplicationException(ExceptionSeverity.ERROR, "Files is empty");
//            }
//
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            // Handle exception as needed, e.g., log it or throw a custom exception
//        }
//
//        return dtos;
//    }

}