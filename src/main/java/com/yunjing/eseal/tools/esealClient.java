package com.yunjing.eseal.tools;


import net.sf.json.JSONObject;
import org.bouncycastle.crypto.digests.SM3Digest;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.Date;


public class esealClient {

    private static int SGD_SM3_SM2 = 0x00020201;

    JFileChooser fileChooser = new JFileChooser();
    FileFilter cer_filter = new JAVAFileFilter("cer");
    FileFilter pdf_filter = new JAVAFileFilter("pdf");
    byte[] digest;
    byte[] sig;
    byte[] total;


    public esealClient() {

        button_cert.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.addChoosableFileFilter(cer_filter);

                fileChooser.showDialog(null,"选择");
                File file = fileChooser.getSelectedFile();

                textField_cert.setText(file.getAbsoluteFile().toString());
                fileChooser.removeChoosableFileFilter(cer_filter);

            }
        });
        button_pdf.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {

                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.addChoosableFileFilter(pdf_filter);

                fileChooser.showDialog(null,"选择");
                File file = fileChooser.getSelectedFile();

                textField_pdf.setText(file.getAbsoluteFile().toString());

                fileChooser.removeChoosableFileFilter(pdf_filter);

                textField_hash.setText("");
                textArea_signature.setText("");

                button_sign.setEnabled(false);
                button_verify.setEnabled(false);
                exportSignatureButton.setEnabled(false);
                try {
                    total = PDFUtils.getBytesFromFile(textField_pdf.getText().trim());
                    if(total!=null){
                        byte[] contents = PDFUtils.getPDFcontentForSign(total);
                        if(contents!=null){
                            // cal digest
                            digest = calSM3Digest(contents);
                            if(hexStringCheckBox.isSelected()){
                                textField_hash.setText(PDFUtils.bytesToHex(digest));
                            }else{
                                String s = new String(digest);
                                textField_hash.setText(s);
                            }

                            try {
                                sig = PDFUtils.getSignatures(textField_pdf.getText().trim());
                                if(sig!=null){
                                    if(hexStringCheckBox.isSelected()){
                                        textArea_signature.setText(PDFUtils.bytesToHex(sig));
                                    }else{
                                        String s = new String(sig);
                                        textArea_signature.setText(s);
                                    }
                                    button_sign.setEnabled(false);
                                    button_verify.setEnabled(true);
                                    exportSignatureButton.setEnabled(true);
                                }else {
                                    button_sign.setEnabled(true);
                                    button_verify.setEnabled(false);
                                    exportSignatureButton.setEnabled(false);
                                }
                            } catch (GeneralSecurityException e1) {
                                e1.printStackTrace();
                            }
                        }
                    }
                } catch (IOException e1) {
                    e1.printStackTrace();
                }

            }
        });
        hexStringCheckBox.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(hexStringCheckBox.isSelected()){
                    if(sig!=null){
                    textArea_signature.setText(PDFUtils.bytesToHex(sig));
                    }
                    textField_hash.setText(PDFUtils.bytesToHex(digest));
                }else{
                    if(sig!=null){
                    String s = new String(sig);
                    textArea_signature.setText(s);
                    }
                    String s = new String(digest);
                    textField_hash.setText(s);
                }
            }
        });
        button_sign.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(textField_ip.getText().length()<1){
                    JOptionPane.showMessageDialog(null, "ip is missing");
                    return;
                }
                String url = "http://"+textField_ip.getText()+"/sealCenter/entities/v1.0/sealSignature";

                if(textField_esid.getText().length()<1){
                    JOptionPane.showMessageDialog(null, "esID is missing");
                    return;
                }
                String param = "esID=" + textField_esid.getText();

                if(textField_keyindex.getText().length()<1){
                    JOptionPane.showMessageDialog(null, "key index is missing");
                    return;
                }

                Integer integer = Integer.decode(textField_keyindex.getText());
                 param = param + "&"+"keyIndex=" + integer; // to int

                if(textField_keypin.getText().length()<1){
                    JOptionPane.showMessageDialog(null, "key auth code is missing");
                    return;
                }
                param = param + "&"+"keyValue=" + textField_keypin.getText();


                param = param + "&"+"signMethod=" + SGD_SM3_SM2;

                if(textField_cert.getText().length()<1){
                    JOptionPane.showMessageDialog(null, "signer cert is missing");
                    return;
                }

                try {

                    String s = readPemCert(textField_cert.getText());
                    byte[] c = java.util.Base64.getDecoder().decode(s);

                    byte[] cc = java.util.Base64.getUrlEncoder().encode(c);
                    String ss = new String(cc);
                    param = param + "&"+"Cert=" + ss;
                } catch (Exception e1) {
                    e1.printStackTrace();
                    JOptionPane.showMessageDialog(null, "something wrong with signer cert 's reading");
                    return;
                }

                if(total == null){
                    JOptionPane.showMessageDialog(null, "invalid pdf file");
                    return;
                }

                String base64encodedString = java.util.Base64.getUrlEncoder().encodeToString(total);
                int length = total.length;
                param = param + "&"+"inDataLen=" + length + "&"+"inData=" + base64encodedString;

                String result = HttpUtils.sendPost(url,param);

                JSONObject jsonObject=JSONObject.fromObject(result);
                SignResult stu=(SignResult)JSONObject.toBean(jsonObject, SignResult.class);
                String saved = stu.savePdf(textField_pdf.getText().trim());
                if(saved.length()>1){
                    JOptionPane.showMessageDialog(null, "signed pdf file " + saved + " success!");
                    return;
                }else{
                    JOptionPane.showMessageDialog(null, "save pdf file failed");
                    return;
                }
            }
        });
        button_verify.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String url = "http://"+ textField_ip.getText()+"/sealCenter/entities/v1.0/verifysealSignature";
                String param;

                if(total == null){
                    JOptionPane.showMessageDialog(null, "invalid pdf file");
                    return;
                }

                String base64encodedString = java.util.Base64.getUrlEncoder().encodeToString(total);
                int length = total.length;
                param = "inDataLen=" + length + "&"+"inData=" + base64encodedString;


                String result = HttpUtils.sendPost(url,param);
                JSONObject jsonObject=JSONObject.fromObject(result);
                String ok = (String)jsonObject.get("msg");

                if(ok.contains("success")){
                    JOptionPane.showMessageDialog(null, "verified pdf success!");
                    return;
                }else{
                    JOptionPane.showMessageDialog(null, "verified pdf failed, error :" + ok);
                    return;
                }
            }
        });
        exportSignatureButton.addMouseListener(new MouseAdapter() {
            /**
             * {@inheritDoc}
             *
             * @param e
             */
            @Override
            public void mouseClicked(MouseEvent e) {
                Date date = new Date();
                String fileName = "sig_" + date.getTime() + ".asn";
                try {
                    FileOutputStream fw = new FileOutputStream(fileName);
                    fw.write(sig);
                    fw.close();
                    JOptionPane.showMessageDialog(null, "export signature as file : " + fileName + " !");
                } catch (IOException e1) {
                    e1.printStackTrace();
                }

            }
        });
    }



    public static void main(String[] args) {


        JFrame frame = new JFrame("esealClient");
        frame.setContentPane(new esealClient().client);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    private JTextField textField_ip;
    private JButton button_pdf;
    private JTextField textField_pdf;
    private JButton button_sign;
    private JButton button_verify;

    private JTextArea textArea_signature;
    private JPanel client;
    private JCheckBox hexStringCheckBox;
    private JButton button_cert;
    private JTextField textField_cert;
    private JTextField textField_keyindex;
    private JTextField textField_keypin;
    private JTextField textField_hash;
    private JTextField textField_esid;
    private JButton exportSignatureButton;


    private static byte[] calSM3Digest(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.reset();
        digest.update(data, 0, data.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        digest.doFinal(resBuf, 0);
        return resBuf;
    }

    private String readPemCert(String certfile) throws IOException {

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


    private String loadObject(BufferedReader br, String type)
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

}
