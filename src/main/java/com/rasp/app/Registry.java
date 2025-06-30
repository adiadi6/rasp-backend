package com.rasp.app;
import platform.helper.HelperManager;
import platform.webservice.ServiceManager;
import com.rasp.app.helper.*;
import com.rasp.app.service.*;
public class Registry {
		public static void register(){
				 HelperManager.getInstance().register(AirlineHelper.getInstance());
				 HelperManager.getInstance().register(BatchHelper.getInstance());
				 HelperManager.getInstance().register(BookingsHelper.getInstance());
				 HelperManager.getInstance().register(FlightHelper.getInstance());
				 HelperManager.getInstance().register(ResourceRoleHelper.getInstance());
				 HelperManager.getInstance().register(RoleResourcePermissionHelper.getInstance());
				 HelperManager.getInstance().register(RoleUserResInstanceHelper.getInstance());
				 HelperManager.getInstance().register(StudentHelper.getInstance());
				 HelperManager.getInstance().register(TravelerHelper.getInstance());
				 HelperManager.getInstance().register(UsersHelper.getInstance());
				 ServiceManager.getInstance().register(new AirlineService());
				 ServiceManager.getInstance().register(new BatchService());
				 ServiceManager.getInstance().register(new BookingsService());
				 ServiceManager.getInstance().register(new FlightService());
				 ServiceManager.getInstance().register(new ResourceRoleService());
				 ServiceManager.getInstance().register(new RoleResourcePermissionService());
				 ServiceManager.getInstance().register(new RoleUserResInstanceService());
				 ServiceManager.getInstance().register(new StudentService());
				 ServiceManager.getInstance().register(new TravelerService());
				 ServiceManager.getInstance().register(new UsersService());
		}
}
