package com.rasp.app.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;

@Component
public class ProjectCopier {




    public  void generator(String target,String project) {
        // Specify the source directory (this must be the path to your existing project)
        String sourceDir = project; // Replace with your source directory

        // Specify the target directory (this will be created dynamically)
        String targetDir = target; // Replace with your desired target directory

        try {
            // Step 1: Create the target directory dynamically
            Path targetPath = Paths.get(targetDir);
            if (!Files.exists(targetPath)) {
                Files.createDirectories(targetPath);  // Creates the target directory and any necessary parent directories
                System.out.println("Target directory created at: " + targetDir);
            }

            // Step 2: Copy the entire project directory (recursive copy)
            copyDirectory(Paths.get(sourceDir), targetPath);

            System.out.println("Project copied successfully.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Method to copy the entire directory and its contents recursively
    private static void copyDirectory(Path sourceDir, Path targetDir) throws IOException {
        // Check if the source directory exists
        if (!Files.exists(sourceDir)) {
            throw new IOException("Source directory does not exist: " + sourceDir);
        }

        // Walk through the source directory and copy all files and subdirectories
        Files.walkFileTree(sourceDir, new SimpleFileVisitor<Path>() {

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                // Copy directories (create them in the target directory)
                Path targetSubDir = targetDir.resolve(sourceDir.relativize(dir));
                if (!Files.exists(targetSubDir)) {
                    Files.createDirectories(targetSubDir);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                // Copy files to the target directory
                Path targetFile = targetDir.resolve(sourceDir.relativize(file));
                Files.copy(file, targetFile, StandardCopyOption.REPLACE_EXISTING);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                // Handle errors during file visit
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
