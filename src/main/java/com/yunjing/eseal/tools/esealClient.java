package com.yunjing.eseal.tools;

import com.google.gson.Gson;
import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.Base64;
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
                            digest = OtherUtils.calSM3Digest(contents);
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
                SealSignInput sealSignInput = new SealSignInput();
                if(textField_ip.getText().length()<1){
                    JOptionPane.showMessageDialog(null, "ip is missing");
                    return;
                }
                String url = "http://"+textField_ip.getText().trim()+"/sealcenter/entities/v1.0/pdf/signature";

                if(textField_keypin.getText().trim().length()<1){
                    JOptionPane.showMessageDialog(null, "key auth code is missing");
                    return;
                }
                sealSignInput.setToken(textField_keypin.getText().trim());

                sealSignInput.setSignMethod(SGD_SM3_SM2);

                if(textField_cert.getText().trim().length()<1){
                    JOptionPane.showMessageDialog(null, "signer cert is missing");
                    return;
                }

                org.bouncycastle.asn1.x509.Certificate cert = OtherUtils.parseCert(textField_cert.getText().trim());
                if(cert!=null) {
                    try {
                        sealSignInput.setCert(Base64.getUrlEncoder().encodeToString(cert.getEncoded()));
                    }catch (Exception e1){
                        e1.printStackTrace();
                        JOptionPane.showMessageDialog(null, "something wrong with signer cert 's reading");
                        return;
                    }
                }else {
                    JOptionPane.showMessageDialog(null, "something wrong with signer cert 's reading");
                    return;
                }

                if(total == null){
                    JOptionPane.showMessageDialog(null, "invalid pdf file");
                    return;
                }

                String base64encodedString = Base64.getUrlEncoder().encodeToString(total);
                sealSignInput.setInData(base64encodedString);
                Gson gson = new Gson();
                String result = HttpUtils.sendPostJson(url,gson.toJson( sealSignInput));

                SignResult stu=gson.fromJson(result, SignResult.class);
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
                String url = "http://"+ textField_ip.getText()+"/sealcenter/entities/v1.0/pdf/verification";
                String param;

                if(total == null){
                    JOptionPane.showMessageDialog(null, "invalid pdf file");
                    return;
                }

                String base64encodedString = Base64.getUrlEncoder().encodeToString(total);
                param = "inData=" + base64encodedString;
                String result = HttpUtils.sendPost(url,param);
                Gson gson = new Gson();
                VerifyResult vok = gson.fromJson(result,VerifyResult.class);
                String ok = vok.getMsg();
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
        pingButton.addMouseListener(new MouseAdapter() {
            /**
             * {@inheritDoc}
             *
             * @param e
             */
            @Override
            public void mouseClicked(MouseEvent e) {

                if(textField_ip.getText().length()<1){
                    JOptionPane.showMessageDialog(null, "ip is missing");
                    return;
                }
                String url = "http://"+textField_ip.getText().trim()+"/sealcenter/entities/v1.0/ping";
                String result = HttpUtils.sendGet(url, null);
                if(result!=null){
                    JOptionPane.showMessageDialog(null, result);
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
    private JTextField textField_keypin;
    private JTextField textField_hash;
    private JButton exportSignatureButton;
    private JButton pingButton;


}
