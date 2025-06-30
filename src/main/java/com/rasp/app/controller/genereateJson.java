package com.rasp.app.controller;

//import com.flightBooking.resource.Fields;
//import com.flightBooking.resource.ResourceConfig;
//import com.flightBooking.resource.ResourceToGenerate;
import com.rasp.app.resource.EnumDto;
import com.rasp.app.resource.MetaDataDto;
import com.rasp.app.resource.WrapperClass;
import com.rasp.app.service.ProjectCopier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import platform.defined.ResourceGenerator;
import platform.util.Util;

import java.io.*;
import java.util.*;

@RestController
public class genereateJson {
@Value("${generate_resource_path}")
        String generate;

    @Value("${project_path}")
    String project;
    @Value("${content_root_package_path}")
    String packageName;

    @Value("${reference_package_path}")
    String reference_package_path;



    StringBuilder javaCode;


    @PostMapping("/api/generateApp")
public String generateJson(@RequestBody WrapperClass wrapperClasses, @RequestParam String appName) throws Exception {

        List<MetaDataDto> dtos = wrapperClasses.getResourceDtos();
        List<EnumDto> enumDtos= wrapperClasses.getEnumDtos();



     ProjectCopier p=new ProjectCopier();
     String appPath=generate+"\\"+appName+"_"+generateRandomString(2);//make sure maintain different directory from copied project

     p.generator(appPath,project);
        if (enumDtos != null && !enumDtos.isEmpty()) {
            for(EnumDto dto:enumDtos) {
                javaCode = new StringBuilder();
                javaCode.append("{\n\n");
                javaCode.append("\"" + dto.getEnum_name().substring(0, 1).toLowerCase() + dto.getEnum_name().substring(1) + "\"" + ": {\n\n");
                javaCode.append("  \"purpose\" : \"POSSIBLE_VALUE\",\n");
                javaCode.append("  \"values\" : {\n");
            List<Map<String, Object>> values  =  dto.getFieldValues();
                Map<String, Object> lastValue = values.get(values.size() - 1);
            for(Map value:values){
               Object name=  value.get("name");
                javaCode.append("    \""+name+"\": {\n\n");
                javaCode.append("     \"id\":\""+name+"\", \n");
                javaCode.append("      \"name\":\""+name+"\" \n");
                if (value.equals(lastValue)) {
                    javaCode.append("   }\n"); // Add closing brace only for the last element
                } else {
                    javaCode.append("   },\n"); // Add closing brace and comma for other elements
                }

            }
            javaCode.append("}\n}\n}");

                String outputPath = appPath+packageName+"/";
                // Create the directory structure if it doesn't exist
                File directory = new File(outputPath);
                if (!directory.exists()) {
                    directory.mkdirs();
                }


                File file = new File(directory,  dto.getEnum_name().substring(0, 1).toLowerCase() + dto.getEnum_name().substring(1) + ".json");

                // Write content to the file using standard Java I/O
                try (FileOutputStream fos = new FileOutputStream(file);
                     OutputStreamWriter writer = new OutputStreamWriter(fos)) {
                    writer.write(javaCode.toString());
                }
            }
        }

    for(MetaDataDto dto:dtos) {


         javaCode = new StringBuilder();
        javaCode.append("{\n\n");
        javaCode.append("\"" +dto.getResource().substring(0, 1).toLowerCase() + dto.getResource().substring(1)+"\""+": {\n\n");
        javaCode.append("  \"cluster\" : \"rasp_db\",\n");
        javaCode.append("  \"ui\" : false,\n");
        javaCode.append("  \"api\" : true,\n");

        javaCode.append("  \"fields\" : {\n");
        List<Map<String, Object>> maps = dto.getFieldValues();
        int size = maps.size();

        for (int i = 0; i < size; i++) {

            Map<String, Object> map = maps.get(i);
            if (i == size - 1) {
                if(dto.getIsUserType()){
                        generateFiedsForAuth() ;
                }
                generateFeildsForLastjson(map);
            }
            else
            generateFeilds(map);



            // If this is the last iteration, call another method

        }

        javaCode.append("   \n");
        javaCode.append("  }\n");
        javaCode.append(" }\n\n");
        javaCode.append("}\n\n");
//        FileWriter fileWriter = new FileWriter(new File("src/main/java/com/flightBooking/decorators", dto.getResource().substring(0, 1).toLowerCase() + dto.getResource().substring(1) + ".json"));
//        fileWriter.write(javaCode.toString());
//        try {
//            fileWriter.close();
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//       }
      //  String outputPath = "C:\\repos\\rasp-iiitb360\\src\\main\\java\\org\\rasp\\iiitb720";
        String outputPath = appPath+packageName+"/";
        // Create the directory structure if it doesn't exist
        File directory = new File(outputPath);
        if (!directory.exists()) {
            directory.mkdirs();
        }


        File file = new File(directory,  dto.getResource().substring(0, 1).toLowerCase() + dto.getResource().substring(1) + ".json");

        // Write content to the file using standard Java I/O
        try (FileOutputStream fos = new FileOutputStream(file);
             OutputStreamWriter writer = new OutputStreamWriter(fos)) {
            writer.write(javaCode.toString());
        }

    }
        String controller_dir = appPath+packageName+"/controller";
        String controller_package = reference_package_path+".controller";
        ResourceGenerator generator = new ResourceGenerator(reference_package_path, appPath+packageName+"/");
        if (!Util.isEmpty(controller_dir)) {
            generator.setController_directory(controller_dir);
            generator.setController_directory_package(controller_package);
        }
        generator.generateCode(appPath+packageName+"/", null);
        if (enumDtos != null && !enumDtos.isEmpty()){
            for (EnumDto dto:enumDtos) {
                javaCode = new StringBuilder();
                javaCode.append("package "+reference_package_path+".controller;\n");
                javaCode.append("import "+reference_package_path+".resource"+"."+toPascalCase(dto.getEnum_name())+";\n");//restrict user to send camel case
                javaCode.append("import java.util.ArrayList;\n");
                javaCode.append("import org.springframework.web.bind.annotation.GetMapping;\n");
                javaCode.append("import java.lang.reflect.Field;\n");
                javaCode.append("import org.springframework.web.bind.annotation.RestController;\n");
                javaCode.append("import java.util.List;\n");
                javaCode.append(" import org.springframework.web.bind.annotation.CrossOrigin;\n");

                javaCode.append("@RestController\n");
                javaCode.append("@CrossOrigin(origins = \"*\")\n");
                javaCode.append("public class " +toPascalCase(dto.getEnum_name())+"Controller"+ "{\n");
                javaCode.append("@GetMapping(\"/api/"+dto.getEnum_name()+"\")\n");
                javaCode.append("  public List<Object>  getEnums() throws IllegalAccessException {\n");
javaCode.append("   Field[] fields = "+toPascalCase(dto.getEnum_name())+".class.getFields();\n");
javaCode.append(" List<Object> names=new ArrayList<>();\n");
javaCode.append(" for(Field f:fields){\n   if(f.getName().startsWith(\"ID\")){\ncontinue;\n}\n Object value = f.get(null);\n names.add(value); \n }\n return names;\n");


        javaCode.append("}\n}");

                String outputPath = appPath+packageName+"/controller";
                // Create the directory structure if it doesn't exist
                File directory = new File(outputPath);
                if (!directory.exists()) {
                    directory.mkdirs();
                }



                File file = new File(directory,  toPascalCase(dto.getEnum_name())+"Controller.java"  );

                // Write content to the file using standard Java I/O
                try (FileOutputStream fos = new FileOutputStream(file);
                     OutputStreamWriter writer = new OutputStreamWriter(fos)) {
                    writer.write(javaCode.toString());
                }
            }
        }

        return "App path :"+ appPath;
}

private void generateFiedsForAuth(){
    javaCode.append("    \"" +"email"+"\""+": {\n\n");
    javaCode.append("     \"name\" : \""+"email"+"\",\n");
    javaCode.append("     \"required\" : \""+false+"\",\n");
    javaCode.append("     \"type\" : \""+"String"+"\"\n");
    javaCode.append("     },\n");
    javaCode.append("    \"" +"password"+"\""+": {\n\n");
    javaCode.append("     \"name\" : \""+"password"+"\",\n");
    javaCode.append("     \"required\" : \""+false+"\",\n");
    javaCode.append("     \"type\" : \""+"String"+"\"\n");
    javaCode.append("     },\n");
    javaCode.append("    \"" +"user_name"+"\""+": {\n\n");
    javaCode.append("     \"name\" : \""+"user_name"+"\",\n");
    javaCode.append("     \"required\" : \""+false+"\",\n");
    javaCode.append("     \"type\" : \""+"String"+"\"\n");
    javaCode.append("     },\n");
}
    private void generateFeilds(Map<String, Object> map) {

          Object name=  map.get("name");
        Object required= map.get("required");
        Object type=map.get("type");
Object is_enum=map.get("is_enum");
Object isFile=map.get("is_file");

       // String foreign=(String) map.get("foreign");
            javaCode.append("    \"" +name+"\""+": {\n\n");


        javaCode.append("     \"name\" : \""+name+"\",\n");
        javaCode.append("     \"required\" : \""+required+"\",\n");
        if( map.get("foreign")!=null){
            Object foreign=(String) map.get("foreign");

            javaCode.append("     \"foreign\" : {\n");
            javaCode.append("      \"resource\" :\""+foreign+"\" \n");
            javaCode.append("      },\n");
        }

        if(map.get("possible_value")!=null){
            Object possible_value=map.get("possible_value");
            javaCode.append("     \"is_enum\" : \""+is_enum+"\",\n");
            javaCode.append("      \"possible_value\" :\""+possible_value+"\", \n");

        }
        if(isFile!=null){
            javaCode.append("     \"is_enum\" : \""+is_enum+"\",\n");
        }
        javaCode.append("     \"type\" : \""+type+"\"\n");



            javaCode.append("     },\n");



    }
    private void generateFeildsForLastjson(Map<String, Object> map) {
        //  for (Map.Entry<String, Object> entry : map.entrySet()) {
        Object name=  map.get("name");
        Object required= map.get("required");
        Object type=map.get("type");
        Object is_enum=map.get("is_enum");
        Object isFile=map.get("is_file");
        // String foreign=(String) map.get("foreign");
        javaCode.append("    \"" +name+"\""+": {\n\n");

        javaCode.append("     \"name\" : \""+name+"\",\n");
        javaCode.append("     \"required\" : \""+required+"\",\n");
        if( map.get("foreign")!=null){
            Object foreign=(String) map.get("foreign");

            javaCode.append("     \"foreign\" : {\n");
            javaCode.append("      \"resource\" :\""+foreign+"\" \n");
            javaCode.append("      },\n");
        }

        if(map.get("possible_value")!=null){
            Object possible_value=map.get("possible_value");
            javaCode.append("     \"is_enum\" : \""+is_enum+"\",\n");
            javaCode.append("      \"possible_value\" :\""+possible_value+"\", \n");

        }
        if(isFile!=null){
            javaCode.append("     \"is_enum\" : \""+is_enum+"\",\n");
        }
        javaCode.append("     \"type\" : \""+type+"\"\n");
        javaCode.append("     }\n");



    }


    public static String generateRandomString(int length) {
        // Generate a random UUID and take the parameter value
        return UUID.randomUUID().toString().substring(0, length);
    }
    public static String toPascalCase(String input) {
        // Split the string by underscore
        String[] parts = input.split("_");

        // StringBuilder to build the PascalCase result
        StringBuilder pascalCaseString = new StringBuilder();

        // Iterate through the parts and capitalize each word
        for (String part : parts) {
            // Capitalize the first letter of each part and append to result
            pascalCaseString.append(part.substring(0, 1).toUpperCase())
                    .append(part.substring(1).toLowerCase());
        }

        return pascalCaseString.toString();
    }

}
