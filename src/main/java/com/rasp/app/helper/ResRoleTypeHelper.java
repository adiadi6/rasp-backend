/*
 * Copyright 2010-2020 M16, Inc. All rights reserved.
 * This software and documentation contain valuable trade
 * secrets and proprietary property belonging to M16, Inc.
 * None of this software and documentation may be copied,
 * duplicated or disclosed without the express
 * written permission of M16, Inc.
 */

package com.rasp.app.helper;

import com.rasp.app.resource.ResRoleType;
import platform.webservice.bi.*;

import platform.helper.BaseHelper;

/*
 ********** This is a generated class Don't modify it.Extend this file for additional functionality **********
 * 
 */
 public class ResRoleTypeHelper extends BaseHelper {
		public ResRoleTypeHelper() {super(new ResRoleType());}
		private static ResRoleTypeHelper instance;
		public static ResRoleTypeHelper getInstance() {if (instance == null)	{instance = new ResRoleTypeHelper();register_birecord();} return instance;}
		public static void register_birecord() {
			BIRecord record;
		}
}