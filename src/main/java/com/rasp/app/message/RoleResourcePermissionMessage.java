/*
 * Copyright 2010-2020 M16, Inc. All rights reserved.
 * This software and documentation contain valuable trade
 * secrets and proprietary property belonging to M16, Inc.
 * None of this software and documentation may be copied,
 * duplicated or disclosed without the express
 * written permission of M16, Inc.
 */

package com.rasp.app.message;

import com.rasp.app.resource.*;
import platform.communication.kafka.BaseMessage;
import platform.resource.BaseResource;
import platform.webservice.BaseService;
import platform.db.*;
import java.util.*;

/*
 ********** This is a generated class Don't modify it.Extend this file for additional functionality **********
 * 
 */
 public class RoleResourcePermissionMessage extends BaseMessage {
		public RoleResourcePermissionMessage() {this(new RoleResourcePermission());}
		public RoleResourcePermissionMessage(BaseResource resource) {super(resource);}
		public RoleResourcePermissionMessage(BaseResource resource,String action) {super(resource,action);}
		public RoleResourcePermissionMessage(BaseResource resource,String action,String sessionId) {super(resource,action,sessionId);}
		public static RoleResourcePermissionMessage of(BaseResource resource,String action) {return new RoleResourcePermissionMessage(resource,action);}
}