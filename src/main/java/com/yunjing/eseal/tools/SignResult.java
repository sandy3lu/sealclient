package com.yunjing.eseal.tools;

import lombok.Data;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;

@Data
public class SignResult {

    String msg;
    int code;
    String outData;
    int outDataLen;

    public String savePdf(String fileName){

        byte[] base64encodedString = java.util.Base64.getDecoder().decode(outData);
        int index = fileName.toLowerCase().indexOf(".pdf");
        String fileName_ori;
        if(index>0){
             fileName_ori = fileName.substring(0,index);
            fileName_ori = fileName_ori + "_signed.pdf";
        }else{
            fileName_ori = fileName + "_signed.pdf";
        }
        File f = new File(fileName_ori);
        if(f.exists()){
            Date date = new Date();
            index = fileName.toLowerCase().indexOf(".pdf");
            fileName_ori = fileName.substring(0,index) + date.getTime() + "_signed.pdf";
        }
        try {
            FileOutputStream fw = new FileOutputStream(fileName_ori);
            fw.write(base64encodedString);
            fw.close();
            return fileName_ori;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }


    public String saveSig(String fileName){

        byte[] base64encodedString = java.util.Base64.getDecoder().decode(outData);
        int index = fileName.toLowerCase().indexOf(".pdf");
        String fileName_ori;
        if(index>0){
            fileName_ori = fileName.substring(0,index);
            fileName_ori = fileName_ori + "_signature.asn";
        }else{
            fileName_ori = fileName + "_signature.asn";
        }
        File f = new File(fileName_ori);
        if(f.exists()){
            Date date = new Date();
            index = fileName.toLowerCase().indexOf(".pdf");
            fileName_ori = fileName.substring(0,index) + date.getTime() + "_signature.asn";
        }
        try {
            FileOutputStream fw = new FileOutputStream(fileName_ori);
            fw.write(base64encodedString);
            fw.close();
            return fileName_ori;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }
}
