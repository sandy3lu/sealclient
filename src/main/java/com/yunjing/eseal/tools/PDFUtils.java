package com.yunjing.eseal.tools;

import com.itextpdf.text.pdf.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;

public class PDFUtils {
    static String SIGNATURE_NAME = "yunjing GuoMi";

    public static byte[] getSignatures(String src) throws IOException, GeneralSecurityException {
        PdfReader reader = new PdfReader(src);
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        for (String name : names) {
                if(name.contains(SIGNATURE_NAME)){
                    PdfDictionary dic = fields.getSignatureDictionary(name);
                    PdfString obj = (PdfString)dic.get(PdfName.CONTENTS);
                    byte[] data = obj.getBytes();
                    return data;
                }
        }
        return null;
    }

    public static byte[] getBytesFromFile(String filename)  {
        try {
            FileInputStream fis = new FileInputStream(filename);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int thebyte = 0;
            while ((thebyte = fis.read()) != -1) {
                baos.write(thebyte);
            }
            fis.close();
            byte[] contents = baos.toByteArray();
            baos.close();
            return contents;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }


    public static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }


    public static byte[] getPDFcontentForSign(byte[] pdf){
        try {
            PdfReader reader = new PdfReader(pdf);
            AcroFields fields = reader.getAcroFields();
            ArrayList<String> names = fields.getSignatureNames();
            for (String name : names) {
                if (name.contains(SIGNATURE_NAME)) {
                    PdfDictionary dic = fields.getSignatureDictionary(name);
                    PdfString obj = (PdfString) dic.get(PdfName.LOCATION);
                    Integer length = Integer.valueOf(obj.toString());
                    return Arrays.copyOfRange(pdf,0,length);
                }
            }
            return pdf;
        }catch (Exception e){
            return null;
        }

    }
}
