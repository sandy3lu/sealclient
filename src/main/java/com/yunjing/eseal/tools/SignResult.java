package com.yunjing.eseal.tools;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;

public class SignResult {

    String msg;
    int code;
    String outData;
    int outDataLen;

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getoutData() {
        return outData;
    }

    public void setoutData(String pdf) {
        this.outData = pdf;
    }

    public int getoutDatalen() {
        return outDataLen;
    }

    public void setoutDatalen(int datalen) {
        this.outDataLen = datalen;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

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

}
