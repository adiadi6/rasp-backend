package com.rasp.app;

import platform.helper.BaseHelper;
import platform.resource.BaseResource;
import platform.util.ApplicationException;

import java.lang.reflect.InvocationTargetException;

public class Tests {

    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, ApplicationException {
        String myClass= "com.example.demo.resource.Batch";
        Class<BaseResource> clazz = (Class<BaseResource>) Class.forName(myClass);

        BaseResource baseResource= clazz.getDeclaredConstructor().newInstance();
//baseResource.convertMapToResource(map);

        String myHelper= "com.example.demo.helper.BatchHelper";
        Class<BaseHelper> clazz2=(Class<BaseHelper>) Class.forName(myHelper) ;
        BaseHelper baseHelper=clazz2.getDeclaredConstructor().newInstance();
        baseHelper.add(baseResource);

        System.out.println( baseResource.getId()+"1111111111111111222222222222222");
    }
}
