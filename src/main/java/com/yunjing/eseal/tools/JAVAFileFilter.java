package com.yunjing.eseal.tools;

import javax.swing.filechooser.FileFilter;
import java.io.File;



public class JAVAFileFilter extends FileFilter {
        String ext;

        public JAVAFileFilter(String ext) {
            this.ext = ext;
        }

        @Override
        public boolean accept(File file) {
            if (file.isDirectory()) {
                return true;
            }
            String fileName = file.getName();
            int index = fileName.lastIndexOf('.');
            if (index > 0 && index < fileName.length() - 1) {

                String extension = fileName.substring(index + 1).toLowerCase();

                if (extension.toLowerCase().equals(ext)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public String getDescription() {
                return "(*." + ext +")";
        }
    }


