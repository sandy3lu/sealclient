package com.yunjing.eseal.tools;

import com.google.gson.Gson;
import org.bouncycastle.asn1.x509.Certificate;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
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
    boolean containSig =false;
    Gson gson = new Gson();

    private static String SIGN="/sealcenter/entities/v1.0/pdf/signature";
    private static String VERIFY="/sealcenter/entities/v1.0/pdf/verification";
    private static String VERIFY_SEPARATE="/sealcenter/entities/v1.0/document/verification";
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
                                if(sig !=null){
                                    if(hexStringCheckBox.isSelected()){
                                        textArea_signature.setText(PDFUtils.bytesToHex(sig));
                                    }else{
                                        String s = new String(sig);
                                        textArea_signature.setText(s);
                                    }
                                    button_sign.setEnabled(false);
                                    button_verify.setEnabled(true);
                                    exportSignatureButton.setEnabled(true);
                                    containSig = true;
                                }else {
                                    button_sign.setEnabled(true);
                                    if(seperate.isSelected()){
                                        button_verify.setEnabled(true);
                                    }else {
                                        button_verify.setEnabled(false);
                                    }
                                    exportSignatureButton.setEnabled(false);
                                    containSig = false;
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
                    if(sig !=null){
                    textArea_signature.setText(PDFUtils.bytesToHex(sig));
                    }
                    textField_hash.setText(PDFUtils.bytesToHex(digest));
                }else{
                    if(sig !=null){
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

                Certificate cert = OtherUtils.parseCert(textField_cert.getText().trim());
                if(cert!=null) {
                    try {
                        sealSignInput.setUrlBase64cert(Base64.getUrlEncoder().encodeToString(cert.getEncoded()));
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
                sealSignInput.setUrlBase64InData(base64encodedString);

                //返回盖了章的pdf
                if(pdfCheckBox.isSelected()) {
                    sealSignInput.setSealPDF(true);
                }else{
                    sealSignInput.setSealPDF(false);
                }

                Gson gson = new Gson();
                //端口替换成443
                String ip = textField_ip.getText().trim();
                int index = ip.lastIndexOf(":");
                String url = "https://"+ip.substring(0,index) + ":443"+ SIGN;
                String result = HttpsUtils.sendPostJson(url,gson.toJson( sealSignInput));
                SignResult stu=gson.fromJson(result, SignResult.class);
                if(stu == null){
                    JOptionPane.showMessageDialog(null, "请求没有返回");
                    return;
                }
                if(stu.outDataLen == 0){
                    JOptionPane.showMessageDialog(null, "error: " + stu.msg);
                    return;
                }
                if(sealSignInput.isSealPDF()) {
                    String saved = stu.savePdf(textField_pdf.getText().trim());
                    if (saved.length() > 1) {
                        JOptionPane.showMessageDialog(null, "signed pdf file " + saved + " success!");
                        return;
                    } else {
                        JOptionPane.showMessageDialog(null, "save pdf file failed");
                        return;
                    }
                }else{
                    //保存签章sig
                    String saved = stu.saveSig(textField_pdf.getText().trim());
                    if (saved.length() > 1) {
                        JOptionPane.showMessageDialog(null, "signature file " + saved + " success!");
                        return;
                    } else {
                        JOptionPane.showMessageDialog(null, "save signature file failed");
                        return;
                    }
                }
            }
        });
        button_verify.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(total == null){
                    JOptionPane.showMessageDialog(null, "invalid pdf file");
                    return;
                }
                String base64encodedString = Base64.getUrlEncoder().encodeToString(total);
                String result=null;
                if(seperate.isSelected()){
                    if(containSig){
                        JOptionPane.showMessageDialog(null, "请选择不包含签名的原文件");
                        return;
                    }
                    String url = "http://"+ textField_ip.getText()+ VERIFY_SEPARATE;
                    SignatureVerifyForm form = new SignatureVerifyForm();
                    form.setUlrBase64Pdf(base64encodedString);
                    byte[] content = PDFUtils.getBytesFromFile(textField_sig.getText().trim());
                    String base64sig = Base64.getUrlEncoder().encodeToString(content);
                    form.setUrlBaseSig(base64sig);
                    result = HttpUtils.sendPostJson(url,gson.toJson(form));
                }else {
                    if(!containSig){
                        JOptionPane.showMessageDialog(null, "请选择包含签名的文件");
                        return;
                    }
                    String url = "http://" + textField_ip.getText() + VERIFY;
                    String param = "signedPDF=" + base64encodedString;
                    result = HttpUtils.sendPost(url, param);
                }
                VerifyResult vok = gson.fromJson(result,VerifyResult.class);
                if(vok.isVerify()){
                    JOptionPane.showMessageDialog(null, "verified pdf success!" );
                    return;
                }else{
                    JOptionPane.showMessageDialog(null, "verified pdf failed, " + vok.getReason());
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
                String pdf = textField_pdf.getText().trim();
                int index = pdf.lastIndexOf(File.separator);
                try {
                    FileOutputStream fw = new FileOutputStream(pdf.substring(0, index+1) + fileName);
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
        seperate.addChangeListener(new ChangeListener() {
            /**
             * Invoked when the target of the listener has changed its state.
             *
             * @param e a ChangeEvent object
             */
            public void stateChanged(ChangeEvent e) {
                if(seperate.isSelected()){
                    sig_asn1Button.setEnabled(true);
                }else{
                    sig_asn1Button.setEnabled(false);
                }
            }
        });


        sig_asn1Button.addMouseListener(new MouseAdapter() {
            /**
             * {@inheritDoc}
             *
             * @param e
             */
            @Override
            public void mouseClicked(MouseEvent e) {
                super.mouseClicked(e);
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.showDialog(null,"选择");
                File file = fileChooser.getSelectedFile();
                textField_sig.setText(file.getAbsoluteFile().toString());
                button_verify.setEnabled(true);
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
    private JCheckBox pdfCheckBox;
    private JTextField textField_sig;
    private JCheckBox seperate;
    private JButton sig_asn1Button;

}
