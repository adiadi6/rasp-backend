package com.rasp.app.resource;

import java.util.List;
import java.util.Map;

public class EnumDto {

    private String enum_name;
    private
    List<Map<String, Object>> fieldValues;

    public List<Map<String, Object>> getFieldValues() {
        return fieldValues;
    }

    public void setFieldValues(List<Map<String, Object>> fieldValues) {
        this.fieldValues = fieldValues;
    }

    public String getEnum_name() {
        return enum_name;
    }

    public void setEnum_name(String enum_name) {
        this.enum_name = enum_name;
    }
}
