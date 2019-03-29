package com.yunjing.eseal.tools;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;

public class OtherUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static Certificate readBase64CertFromString(String certdata)
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        byte[] contents = Base64.decode(certdata);
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(contents));
        return cert;
    }

    public static org.bouncycastle.asn1.x509.Certificate parseCert(String fileName){
        if(fileName.endsWith("p7b")){
            String p7b = readToString(fileName);
            ArrayList<org.bouncycastle.asn1.x509.Certificate> certificates = extractCerts(p7b);
            if(certificates!=null) {
                org.bouncycastle.asn1.x509.Certificate smCertificate = certificates.get(certificates.size() - 1);
                return smCertificate;
            }
        }
        if(fileName.endsWith("cer")){
            X509Certificate cert = readPEMCert(fileName);
            if(cert!=null) {
                try {
                    return org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());
                }catch (Exception e){
                    e.printStackTrace();
                    return null;
                }
            }
        }
        return null;
    }



    public static ArrayList<org.bouncycastle.asn1.x509.Certificate> extractCerts(String p7b) {
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(Base64.decode(p7b));
            CollectionStore<X509CertificateHolder> certStore =
                    (CollectionStore<X509CertificateHolder>) cmsSignedData.getCertificates();
            Iterator iterator = certStore.iterator();
            ArrayList<org.bouncycastle.asn1.x509.Certificate> certificates = new ArrayList();
            while (iterator.hasNext()) {
                X509CertificateHolder certificateHolder = (X509CertificateHolder) iterator.next();
                org.bouncycastle.asn1.x509.Certificate certificate = certificateHolder.toASN1Structure();
                certificates.add(certificate);
            }
            return certificates;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }


    public static String readToString(String fileName) {
        String encoding = "UTF-8";
        File file = new File(fileName);
        Long filelength = file.length();
        byte[] filecontent = new byte[filelength.intValue()];
        try {
            FileInputStream in = new FileInputStream(file);
            in.read(filecontent);
            in.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        try {
            return new String(filecontent, encoding);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static X509Certificate readPEMCert(String fileName) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(new FileInputStream(fileName));
            return cert;
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String readPemCert(String certfile) throws IOException {

        String BEGIN = "-----BEGIN ";
        BufferedReader br = new BufferedReader(new FileReader(certfile));
        String line = br.readLine();
        while (line != null && !line.startsWith(BEGIN))
        {
            line = br.readLine();
        }
        if (line != null)
        {
            line = line.substring(BEGIN.length());
            int index = line.indexOf('-');
            String type = line.substring(0, index);

            if (index > 0)
            {
                return loadObject(br, type);
            }
        }
        return null;
    }

    private static String loadObject(BufferedReader br, String type)
            throws IOException
    {
        String END = "-----END ";
        String          line;
        String          endMarker = END + type;
        StringBuffer    buf = new StringBuffer();

        while ((line = br.readLine()) != null)
        {
            if (line.indexOf(":") >= 0)
            {
                int index = line.indexOf(':');
                String hdr = line.substring(0, index);
                String value = line.substring(index + 1).trim();
                continue;
            }

            if (line.indexOf(endMarker) != -1)
            {
                break;
            }

            buf.append(line.trim());
        }

        if (line == null)
        {
            throw new IOException(endMarker + " not found");
        }

        return buf.toString();
    }


    public static byte[] calSM3Digest(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.reset();
        digest.update(data, 0, data.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        digest.doFinal(resBuf, 0);
        return resBuf;
    }
}
