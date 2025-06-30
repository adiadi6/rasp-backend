/*
 * Copyright 2010-2020 M16, Inc. All rights reserved.
 * This software and documentation contain valuable trade
 * secrets and proprietary property belonging to M16, Inc.
 * None of this software and documentation may be copied,
 * duplicated or disclosed without the express
 * written permission of M16, Inc.
 */

package com.rasp.app.controller;

//import platform.webservice.BaseController;
import com.rasp.app.resource.ResRoleType;
import com.rasp.app.service.ResRoleTypeService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.stereotype.Controller;

//import platform.webservice.BaseController;


/*
 ********** This is a generated class Don't modify it.Extend this file for additional functionality **********
 * 
 */
@Controller
@RequestMapping("/api/res_role_type")
 public class ResRoleTypeController extends BaseController {
		public ResRoleTypeController() {super(new ResRoleType(),new ResRoleTypeService());}
}