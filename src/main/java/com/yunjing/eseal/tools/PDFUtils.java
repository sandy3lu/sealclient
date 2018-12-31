package com.yunjing.eseal.tools;

import com.itextpdf.text.pdf.*;

import java.io.*;
import java.security.GeneralSecurityException;
import java.util.ArrayList;


public class PDFUtils {

    static  byte[] PDF_END = new byte[]{0x45, 0x4f,0x46, 0x0a};
    static String SIGNATURE_NAME = "yunjing GuoMi";

    public static byte[] getBytesFromFile(String filename) throws IOException {
        FileInputStream fis=new FileInputStream(filename);
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        int thebyte=0;
        while((thebyte=fis.read())!=-1)
        {
            baos.write(thebyte);
        }
        fis.close();
        byte[] contents=baos.toByteArray();
        baos.close();
        return contents;
    }

    private static int ByteIndexOf(byte[] srcBytes, byte[] searchBytes)
    {
        if (srcBytes == null) { return -1; }
        if (searchBytes == null) { return -1; }
        if (srcBytes.length == 0) { return -1; }
        if (searchBytes.length == 0) { return -1; }
        if (srcBytes.length < searchBytes.length) { return -1; }
        for (int i = 0; i <= srcBytes.length - searchBytes.length; i++)
        {
            if (srcBytes[i] == searchBytes[0])
            {
                //System.out.printf("%d: %d %d %d %d\n",i, srcBytes[i],srcBytes[i+1],srcBytes[i+2],srcBytes[i+3]);
                if (searchBytes.length == 1) { return i; }
                boolean flag = true;
                for (int j = 1; j < searchBytes.length; j++)
                {
                    if (srcBytes[i + j] != searchBytes[j])
                    {
                        flag = false;
                        break;
                    }
                }
                if (flag) { return i; }
            }
        }
        return -1;
    }


    public static byte[] getPDFcontentForSign(byte[] pdf){

        int index = ByteIndexOf(pdf,PDF_END);
        if(index>0){
            byte[] result = new byte[index +PDF_END.length];
            System.arraycopy(pdf, 0, result, 0, result.length);
            return result;
        }else {
            return null;
        }


    }

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
}
