/*
 * Copyright 2010-2020 M16, Inc. All rights reserved.
 * This software and documentation contain valuable trade
 * secrets and proprietary property belonging to M16, Inc.
 * None of this software and documentation may be copied,
 * duplicated or disclosed without the express
 * written permission of M16, Inc.
 */

package com.rasp.app.resource;

import com.fasterxml.jackson.annotation.JsonIgnore;
import platform.exception.ExceptionEnum;
 import platform.resource.BaseResource;
import platform.util.*;
import org.springframework.stereotype.Component;
import platform.db.*;
import java.util.*;
import com.rasp.app.message.*;
import com.rasp.app.helper.*;
import com.rasp.app.service.*;

/*
 ********** This is a generated class Don't modify it.Extend this file for additional functionality **********
 * 
 */
@Component
 public class RoleUserResInstance extends BaseResource {
	private String id = null;
	private String g_created_by_id = null;
	private String g_created_by_name = null;
	private String g_modified_by_id = null;
	private String g_modified_by_name = null;
	private Long g_creation_time = null;
	private Long g_modify_time = null;
	private String g_soft_delete = null;
	private String g_status = null;
	private String archived = null;
	private Long archived_time = null;
	private String role_id = null;
	private String role_name = null;
	private String resource_id = null;
	private String keycloak_user_id = null;
	private String user_name = null;
	private String resource_name = null;
	private String rasp_user_id = null;
	private Map<String, Object> extra_data = null;

	public static String FIELD_ID = "id";
	public static String FIELD_G_CREATED_BY_ID = "g_created_by_id";
	public static String FIELD_G_CREATED_BY_NAME = "g_created_by_name";
	public static String FIELD_G_MODIFIED_BY_ID = "g_modified_by_id";
	public static String FIELD_G_MODIFIED_BY_NAME = "g_modified_by_name";
	public static String FIELD_G_CREATION_TIME = "g_creation_time";
	public static String FIELD_G_MODIFY_TIME = "g_modify_time";
	public static String FIELD_G_SOFT_DELETE = "g_soft_delete";
	public static String FIELD_G_STATUS = "g_status";
	public static String FIELD_ARCHIVED = "archived";
	public static String FIELD_ARCHIVED_TIME = "archived_time";
	public static String FIELD_ROLE_ID = "role_id";
	public static String FIELD_ROLE_NAME = "role_name";
	public static String FIELD_RESOURCE_ID = "resource_id";
	public static String FIELD_KEYCLOAK_USER_ID = "keycloak_user_id";
	public static String FIELD_USER_NAME = "user_name";
	public static String FIELD_RESOURCE_NAME = "resource_name";
	public static String FIELD_RASP_USER_ID = "rasp_user_id";
	public static String FIELD_EXTRA_DATA = "extra_data";

	private static final long serialVersionUID = 1L;
	public final static ResourceMetaData metaData = new ResourceMetaData("role_user_res_instance");

	static {
		metaData.setCheckBeforeAdd(false);
		metaData.setCheckBeforeUpdate(false);

		metaData.setAllow_duplicate_name(false);
		Field idField = new Field("id", "String");
		idField.setIndexed(true);
		idField.setRequired(true);
		idField.setLength(128);
		metaData.addField(idField);

		Field g_created_by_idField = new Field("g_created_by_id", "String");
		g_created_by_idField.setLength(128);
		metaData.addField(g_created_by_idField);

		Field g_created_by_nameField = new Field("g_created_by_name", "String");
		g_created_by_nameField.setLength(128);
		metaData.addField(g_created_by_nameField);

		Field g_modified_by_idField = new Field("g_modified_by_id", "String");
		g_modified_by_idField.setLength(128);
		metaData.addField(g_modified_by_idField);

		Field g_modified_by_nameField = new Field("g_modified_by_name", "String");
		g_modified_by_nameField.setLength(128);
		metaData.addField(g_modified_by_nameField);

		Field g_creation_timeField = new Field("g_creation_time", "long");
		metaData.addField(g_creation_timeField);

		Field g_modify_timeField = new Field("g_modify_time", "long");
		metaData.addField(g_modify_timeField);

		Field g_soft_deleteField = new Field("g_soft_delete", "String");
		g_soft_deleteField.setDefaultValue("N");
		g_soft_deleteField.setLength(1);
		metaData.addField(g_soft_deleteField);

		Field g_statusField = new Field("g_status", "String");
		g_statusField.setIndexed(true);
		g_statusField.setLength(32);
		metaData.addField(g_statusField);

		Field archivedField = new Field("archived", "String");
		archivedField.setIndexed(true);
		archivedField.setDefaultValue("N");
		archivedField.setLength(1);
		metaData.addField(archivedField);

		Field archived_timeField = new Field("archived_time", "long");
		metaData.addField(archived_timeField);

		Field role_idField = new Field("role_id", "String");
		role_idField.setRequired(true);
		role_idField.setLength(128);
		metaData.addField(role_idField);

		Field role_nameField = new Field("role_name", "String");
		role_nameField.setLength(40);
		metaData.addField(role_nameField);

		Field resource_idField = new Field("resource_id", "String");
		resource_idField.setIndexed(true);
		resource_idField.setRequired(true);
		resource_idField.setLength(128);
		metaData.addField(resource_idField);

		Field keycloak_user_idField = new Field("keycloak_user_id", "String");
		keycloak_user_idField.setIndexed(true);
		keycloak_user_idField.setLength(128);
		metaData.addField(keycloak_user_idField);

		Field user_nameField = new Field("user_name", "String");
		user_nameField.setIndexed(true);
		user_nameField.setLength(128);
		metaData.addField(user_nameField);

		Field resource_nameField = new Field("resource_name", "String");
		resource_nameField.setIndexed(true);
		resource_nameField.setLength(128);
		metaData.addField(resource_nameField);

		Field rasp_user_idField = new Field("rasp_user_id", "String");
		rasp_user_idField.setIndexed(true);
		rasp_user_idField.setLength(128);
		metaData.addField(rasp_user_idField);

		Field extra_dataField = new Field("extra_data", "Map");
		extra_dataField.setValueType("Object");
		metaData.addField(extra_dataField);


		metaData.setTableName("role_user_res_instance");

		metaData.setCluster("DB_ACCOUNT");
	}

	public RoleUserResInstance() {this.setId(Util.getUniqueId());}
	public RoleUserResInstance(String id) {this.setId(id);}

	public RoleUserResInstance(RoleUserResInstance obj) {
		this.id = obj.id;
		this.g_created_by_id = obj.g_created_by_id;
		this.g_created_by_name = obj.g_created_by_name;
		this.g_modified_by_id = obj.g_modified_by_id;
		this.g_modified_by_name = obj.g_modified_by_name;
		this.g_creation_time = obj.g_creation_time;
		this.g_modify_time = obj.g_modify_time;
		this.g_soft_delete = obj.g_soft_delete;
		this.g_status = obj.g_status;
		this.archived = obj.archived;
		this.archived_time = obj.archived_time;
		this.role_id = obj.role_id;
		this.role_name = obj.role_name;
		this.resource_id = obj.resource_id;
		this.keycloak_user_id = obj.keycloak_user_id;
		this.user_name = obj.user_name;
		this.resource_name = obj.resource_name;
		this.rasp_user_id = obj.rasp_user_id;
		this.extra_data = obj.extra_data;
	}

	public ResourceMetaData getMetaData() {
		return metaData;
	}

	private void setDefaultValues() {
		if(g_soft_delete == null)
			g_soft_delete = "N";
		if(archived == null)
			archived = "N";
	}

	public Map<String, Object> convertResourceToMap(HashMap<String, Object> map) {
		if(id != null)
			map.put("id", id);
		if(g_created_by_id != null)
			map.put("g_created_by_id", g_created_by_id);
		if(g_created_by_name != null)
			map.put("g_created_by_name", g_created_by_name);
		if(g_modified_by_id != null)
			map.put("g_modified_by_id", g_modified_by_id);
		if(g_modified_by_name != null)
			map.put("g_modified_by_name", g_modified_by_name);
		if(g_creation_time != null)
			map.put("g_creation_time", g_creation_time);
		if(g_modify_time != null)
			map.put("g_modify_time", g_modify_time);
		if(g_soft_delete != null)
			map.put("g_soft_delete", g_soft_delete);
		if(g_status != null)
			map.put("g_status", g_status);
		if(archived != null)
			map.put("archived", archived);
		if(archived_time != null)
			map.put("archived_time", archived_time);
		if(role_id != null)
			map.put("role_id", role_id);
		if(role_name != null)
			map.put("role_name", role_name);
		if(resource_id != null)
			map.put("resource_id", resource_id);
		if(keycloak_user_id != null)
			map.put("keycloak_user_id", keycloak_user_id);
		if(user_name != null)
			map.put("user_name", user_name);
		if(resource_name != null)
			map.put("resource_name", resource_name);
		if(rasp_user_id != null)
			map.put("rasp_user_id", rasp_user_id);
		if(extra_data != null)
			map.put("extra_data", extra_data);
		return map;
	}

	public Map<String, Object> validateAndConvertResourceToMap(HashMap<String,Object> map,boolean add) throws ApplicationException {
		if(validateId(add))
			map.put("id", id);
		if(g_created_by_id != null)
			map.put("g_created_by_id", g_created_by_id);
		if(g_created_by_name != null)
			map.put("g_created_by_name", g_created_by_name);
		if(g_modified_by_id != null)
			map.put("g_modified_by_id", g_modified_by_id);
		if(g_modified_by_name != null)
			map.put("g_modified_by_name", g_modified_by_name);
		if(g_creation_time != null)
			map.put("g_creation_time", g_creation_time);
		if(g_modify_time != null)
			map.put("g_modify_time", g_modify_time);
		if(g_soft_delete != null)
			map.put("g_soft_delete", g_soft_delete);
		if(g_status != null)
			map.put("g_status", g_status);
		if(archived != null)
			map.put("archived", archived);
		if(archived_time != null)
			map.put("archived_time", archived_time);
		if(validateRole_id(add))
			map.put("role_id", role_id);
		if(role_name != null)
			map.put("role_name", role_name);
		if(validateResource_id(add))
			map.put("resource_id", resource_id);
		if(keycloak_user_id != null)
			map.put("keycloak_user_id", keycloak_user_id);
		if(user_name != null)
			map.put("user_name", user_name);
		if(resource_name != null)
			map.put("resource_name", resource_name);
		if(rasp_user_id != null)
			map.put("rasp_user_id", rasp_user_id);
		if(extra_data != null)
			map.put("extra_data", extra_data);
		return map;
	}

	public Map<String, Object> convertResourceToPrimaryMap(HashMap<String, Object> map) {
		return map;
	}

	@SuppressWarnings("unchecked")
	public void convertMapToResource(Map<String, Object> map) {
		id = (String) map.get("id");
		g_created_by_id = (String) map.get("g_created_by_id");
		g_created_by_name = (String) map.get("g_created_by_name");
		g_modified_by_id = (String) map.get("g_modified_by_id");
		g_modified_by_name = (String) map.get("g_modified_by_name");
		g_creation_time = (map.get("g_creation_time") == null ? null : ((Number) map.get("g_creation_time")).longValue());
		g_modify_time = (map.get("g_modify_time") == null ? null : ((Number) map.get("g_modify_time")).longValue());
		g_soft_delete = (String) map.get("g_soft_delete");
		g_status = (String) map.get("g_status");
		archived = (String) map.get("archived");
		archived_time = (map.get("archived_time") == null ? null : ((Number) map.get("archived_time")).longValue());
		role_id = (String) map.get("role_id");
		role_name = (String) map.get("role_name");
		resource_id = (String) map.get("resource_id");
		keycloak_user_id = (String) map.get("keycloak_user_id");
		user_name = (String) map.get("user_name");
		resource_name = (String) map.get("resource_name");
		rasp_user_id = (String) map.get("rasp_user_id");
		extra_data = (Map<String, Object>) map.get("extra_data");
	}

	@SuppressWarnings("unchecked")
	public void convertTypeUnsafeMapToResource(Map<String, Object> map) {
		Object idObj = map.get("id");
		if(idObj != null)
			id = idObj.toString();

		Object g_created_by_idObj = map.get("g_created_by_id");
		if(g_created_by_idObj != null)
			g_created_by_id = g_created_by_idObj.toString();

		Object g_created_by_nameObj = map.get("g_created_by_name");
		if(g_created_by_nameObj != null)
			g_created_by_name = g_created_by_nameObj.toString();

		Object g_modified_by_idObj = map.get("g_modified_by_id");
		if(g_modified_by_idObj != null)
			g_modified_by_id = g_modified_by_idObj.toString();

		Object g_modified_by_nameObj = map.get("g_modified_by_name");
		if(g_modified_by_nameObj != null)
			g_modified_by_name = g_modified_by_nameObj.toString();

		Object g_creation_timeObj = map.get("g_creation_time");
		if(g_creation_timeObj != null)
			g_creation_time = new Long(g_creation_timeObj.toString());

		Object g_modify_timeObj = map.get("g_modify_time");
		if(g_modify_timeObj != null)
			g_modify_time = new Long(g_modify_timeObj.toString());

		Object g_soft_deleteObj = map.get("g_soft_delete");
		if(g_soft_deleteObj != null)
			g_soft_delete = g_soft_deleteObj.toString();

		Object g_statusObj = map.get("g_status");
		if(g_statusObj != null)
			g_status = g_statusObj.toString();

		Object archivedObj = map.get("archived");
		if(archivedObj != null)
			archived = archivedObj.toString();

		Object archived_timeObj = map.get("archived_time");
		if(archived_timeObj != null)
			archived_time = new Long(archived_timeObj.toString());

		Object role_idObj = map.get("role_id");
		if(role_idObj != null)
			role_id = role_idObj.toString();

		Object role_nameObj = map.get("role_name");
		if(role_nameObj != null)
			role_name = role_nameObj.toString();

		Object resource_idObj = map.get("resource_id");
		if(resource_idObj != null)
			resource_id = resource_idObj.toString();

		Object keycloak_user_idObj = map.get("keycloak_user_id");
		if(keycloak_user_idObj != null)
			keycloak_user_id = keycloak_user_idObj.toString();

		Object user_nameObj = map.get("user_name");
		if(user_nameObj != null)
			user_name = user_nameObj.toString();

		Object resource_nameObj = map.get("resource_name");
		if(resource_nameObj != null)
			resource_name = resource_nameObj.toString();

		Object rasp_user_idObj = map.get("rasp_user_id");
		if(rasp_user_idObj != null)
			rasp_user_id = rasp_user_idObj.toString();

		extra_data = (Map<String, Object>) map.get("extra_data");
	}

	public void convertPrimaryMapToResource(Map<String, Object> map) {
	}

	public void convertTypeUnsafePrimaryMapToResource(Map<String, Object> map) {
	}

	public String getId() {
		return id;
	}

	public String getIdEx() {
		return id != null ? id : "";
	}

	public void setId(String id) {
		this.id = id;
	}

	public void unSetId() {
		this.id = null;
	}

	public boolean validateId(boolean add) throws ApplicationException {
		if(add && id == null)
			throw new ApplicationException(ExceptionSeverity.ERROR, "Requierd validation Failed[id]");
		return id != null;
	}

	public String getG_created_by_id() {
		return g_created_by_id;
	}

	public String getG_created_by_idEx() {
		return g_created_by_id != null ? g_created_by_id : "";
	}

	public void setG_created_by_id(String g_created_by_id) {
		this.g_created_by_id = g_created_by_id;
	}

	public void unSetG_created_by_id() {
		this.g_created_by_id = null;
	}

	public String getG_created_by_name() {
		return g_created_by_name;
	}

	public String getG_created_by_nameEx() {
		return g_created_by_name != null ? g_created_by_name : "";
	}

	public void setG_created_by_name(String g_created_by_name) {
		this.g_created_by_name = g_created_by_name;
	}

	public void unSetG_created_by_name() {
		this.g_created_by_name = null;
	}

	public String getG_modified_by_id() {
		return g_modified_by_id;
	}

	public String getG_modified_by_idEx() {
		return g_modified_by_id != null ? g_modified_by_id : "";
	}

	public void setG_modified_by_id(String g_modified_by_id) {
		this.g_modified_by_id = g_modified_by_id;
	}

	public void unSetG_modified_by_id() {
		this.g_modified_by_id = null;
	}

	public String getG_modified_by_name() {
		return g_modified_by_name;
	}

	public String getG_modified_by_nameEx() {
		return g_modified_by_name != null ? g_modified_by_name : "";
	}

	public void setG_modified_by_name(String g_modified_by_name) {
		this.g_modified_by_name = g_modified_by_name;
	}

	public void unSetG_modified_by_name() {
		this.g_modified_by_name = null;
	}

	public Long getG_creation_time() {
		return g_creation_time;
	}

	public long getG_creation_timeEx() {
		return g_creation_time != null ? g_creation_time : 0L;
	}

	public void setG_creation_time(long g_creation_time) {
		this.g_creation_time = g_creation_time;
	}

	@JsonIgnore
	public void setG_creation_time(Long g_creation_time) {
		this.g_creation_time = g_creation_time;
	}

	public void unSetG_creation_time() {
		this.g_creation_time = null;
	}

	public Long getG_modify_time() {
		return g_modify_time;
	}

	public long getG_modify_timeEx() {
		return g_modify_time != null ? g_modify_time : 0L;
	}

	public void setG_modify_time(long g_modify_time) {
		this.g_modify_time = g_modify_time;
	}

	@JsonIgnore
	public void setG_modify_time(Long g_modify_time) {
		this.g_modify_time = g_modify_time;
	}

	public void unSetG_modify_time() {
		this.g_modify_time = null;
	}

	public String getG_soft_delete() {
		return g_soft_delete != null ? g_soft_delete : "N";
	}

	public void setG_soft_delete(String g_soft_delete) {
		this.g_soft_delete = g_soft_delete;
	}

	public void unSetG_soft_delete() {
		this.g_soft_delete = "N";
	}

	public String getG_status() {
		return g_status;
	}

	public String getG_statusEx() {
		return g_status != null ? g_status : "";
	}

	public void setG_status(String g_status) {
		this.g_status = g_status;
	}

	public void unSetG_status() {
		this.g_status = null;
	}

	public String getArchived() {
		return archived != null ? archived : "N";
	}

	public void setArchived(String archived) {
		this.archived = archived;
	}

	public void unSetArchived() {
		this.archived = "N";
	}

	public Long getArchived_time() {
		return archived_time;
	}

	public long getArchived_timeEx() {
		return archived_time != null ? archived_time : 0L;
	}

	public void setArchived_time(long archived_time) {
		this.archived_time = archived_time;
	}

	@JsonIgnore
	public void setArchived_time(Long archived_time) {
		this.archived_time = archived_time;
	}

	public void unSetArchived_time() {
		this.archived_time = null;
	}

	public String getRole_id() {
		return role_id;
	}

	public String getRole_idEx() {
		return role_id != null ? role_id : "";
	}

	public void setRole_id(String role_id) {
		this.role_id = role_id;
	}

	public void unSetRole_id() {
		this.role_id = null;
	}

	public boolean validateRole_id(boolean add) throws ApplicationException {
		if(add && role_id == null)
			throw new ApplicationException(ExceptionSeverity.ERROR, "Requierd validation Failed[role_id]");
		return role_id != null;
	}

	public String getRole_name() {
		return role_name;
	}

	public String getRole_nameEx() {
		return role_name != null ? role_name : "";
	}

	public void setRole_name(String role_name) {
		this.role_name = role_name;
	}

	public void unSetRole_name() {
		this.role_name = null;
	}

	public String getResource_id() {
		return resource_id;
	}

	public String getResource_idEx() {
		return resource_id != null ? resource_id : "";
	}

	public void setResource_id(String resource_id) {
		this.resource_id = resource_id;
	}

	public void unSetResource_id() {
		this.resource_id = null;
	}

	public boolean validateResource_id(boolean add) throws ApplicationException {
		if(add && resource_id == null)
			throw new ApplicationException(ExceptionSeverity.ERROR, "Requierd validation Failed[resource_id]");
		return resource_id != null;
	}

	public String getKeycloak_user_id() {
		return keycloak_user_id;
	}

	public String getKeycloak_user_idEx() {
		return keycloak_user_id != null ? keycloak_user_id : "";
	}

	public void setKeycloak_user_id(String keycloak_user_id) {
		this.keycloak_user_id = keycloak_user_id;
	}

	public void unSetKeycloak_user_id() {
		this.keycloak_user_id = null;
	}

	public String getUser_name() {
		return user_name;
	}

	public String getUser_nameEx() {
		return user_name != null ? user_name : "";
	}

	public void setUser_name(String user_name) {
		this.user_name = user_name;
	}

	public void unSetUser_name() {
		this.user_name = null;
	}

	public String getResource_name() {
		return resource_name;
	}

	public String getResource_nameEx() {
		return resource_name != null ? resource_name : "";
	}

	public void setResource_name(String resource_name) {
		this.resource_name = resource_name;
	}

	public void unSetResource_name() {
		this.resource_name = null;
	}

	public String getRasp_user_id() {
		return rasp_user_id;
	}

	public String getRasp_user_idEx() {
		return rasp_user_id != null ? rasp_user_id : "";
	}

	public void setRasp_user_id(String rasp_user_id) {
		this.rasp_user_id = rasp_user_id;
	}

	public void unSetRasp_user_id() {
		this.rasp_user_id = null;
	}

	public Map<String, Object> getExtra_data() {
		return extra_data;
	}

	public Object getExtra_data(String key) {
		return extra_data == null ? null : extra_data.get(key);
	}

	public void setExtra_data(Map<String, Object> extra_data) {
		this.extra_data = extra_data;
	}

	public void setExtra_data(String key, Object value) {
		if(extra_data == null)
			extra_data = new HashMap<String, Object>();
		extra_data.put(key, value);
	}

	public void unSetExtra_data() {
		this.extra_data = null;
	}
	public String getCluster() {
		return "DB_ACCOUNT";
	}
	public String getClusterType() {
		return "REPLICATED";
	}
	public  Class<?> getResultClass() {return RoleUserResInstanceResult.class;};
	public  Class<?> getMessageClass() {return RoleUserResInstanceMessage.class;};
	public  Class<?> getHelperClass() {return RoleUserResInstanceHelper.class;};
	public  Class<?> getServiceClass() {return RoleUserResInstanceService.class;};
}