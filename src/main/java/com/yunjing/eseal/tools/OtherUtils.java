package com.yunjing.eseal.tools;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

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
}
