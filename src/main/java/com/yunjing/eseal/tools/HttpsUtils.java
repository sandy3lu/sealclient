package com.yunjing.eseal.tools;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class HttpsUtils {

    private static class DefaultTrustManager implements X509TrustManager {

        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    private static HttpsURLConnection getHttpsURLConnection(String uri, String method) throws IOException {
        SSLContext ctx = null;
        try {
            ctx = SSLContext.getInstance("TLS");
            ctx.init(new KeyManager[0], new TrustManager[] { new DefaultTrustManager() }, new SecureRandom());
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SSLSocketFactory ssf = ctx.getSocketFactory();

        URL url = new URL(uri);
        HttpsURLConnection httpsConn = (HttpsURLConnection) url.openConnection();
        httpsConn.setSSLSocketFactory(ssf);
        httpsConn.setHostnameVerifier(new HostnameVerifier() {

            public boolean verify(String arg0, SSLSession arg1) {
                return true;
            }
        });
        httpsConn.setRequestMethod(method);
        httpsConn.setDoInput(true);
        httpsConn.setDoOutput(true);
        return httpsConn;
    }

    private static byte[] getBytesFromStream(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] kb = new byte[1024];
        int len;
        while ((len = is.read(kb)) != -1) {
            baos.write(kb, 0, len);
        }
        byte[] bytes = baos.toByteArray();
        baos.close();
        is.close();
        return bytes;
    }

    private static void setBytesToStream(OutputStream os, byte[] bytes) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        byte[] kb = new byte[1024];
        int len;
        while ((len = bais.read(kb)) != -1) {
            os.write(kb, 0, len);
        }
        os.flush();
        os.close();
        bais.close();
    }

    public static byte[] doGet(String uri) throws IOException {
        HttpsURLConnection httpsConn = getHttpsURLConnection(uri, "GET");
        return getBytesFromStream(httpsConn.getInputStream());
    }

    public static byte[] doPost(String uri, String data) throws IOException {
        HttpsURLConnection httpsConn = getHttpsURLConnection(uri, "POST");
        setBytesToStream(httpsConn.getOutputStream(), data.getBytes());
        return getBytesFromStream(httpsConn.getInputStream());
    }

    public static String sendPostJson(String url_param, String jsonparam) {
        String result = "";
        BufferedReader in = null;

        try {
            // 打开URL连接
            HttpsURLConnection httpsConn = getHttpsURLConnection(url_param, "POST");
            // 设置属性
            httpsConn.setRequestProperty("Content-Type",
                    "application/json");
            httpsConn.setUseCaches(false);
            httpsConn.setInstanceFollowRedirects(true);
            // 获取HttpURLConnection对象对应的输出流
            DataOutputStream out = new DataOutputStream(httpsConn.getOutputStream());
            out.write(jsonparam.getBytes("utf-8"));
            // flush输出流的缓冲
            out.flush();
            out.close();
            // 定义BufferedReader输入流来读取URL的响应，设置编码方式
            in = new BufferedReader(new InputStreamReader(httpsConn.getInputStream(), "UTF-8"));
            String line;
            // 读取返回的内容
            while ((line = in.readLine()) != null) {
                result += line;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return result;
    }
}
