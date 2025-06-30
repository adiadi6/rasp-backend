package com.rasp.app.resource;



import java.util.List;
import java.util.Map;

public class MetaDataDto {

    private String resource;
    private boolean isUserType;

    private
    List<Map<String, Object>> fieldValues;

    public boolean getIsUserType() {
        return isUserType;
    }

    public void setIsUserType(boolean isUserType) {
        this.isUserType = isUserType;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public List<Map<String, Object>> getFieldValues() {
        return fieldValues;
    }

    public void setFieldValues(List<Map<String, Object>> fieldValues) {
        this.fieldValues = fieldValues;


    }

}