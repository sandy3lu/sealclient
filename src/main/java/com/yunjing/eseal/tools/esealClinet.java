package com.yunjing.eseal.tools;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.digests.SM3Digest;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static java.util.Base64.getEncoder;

public class esealClinet {

    static ASN1ObjectIdentifier SM2signatureAlgorithm = new ASN1ObjectIdentifier("1.2.156.10197.1.501");

    JFileChooser fileChooser = new JFileChooser();
    FileFilter cer_filter = new JAVAFileFilter("cer");
    FileFilter pdf_filter = new JAVAFileFilter("pdf");
    byte[] digest;
    byte[] sig;
    byte[] total;


    public esealClinet() {

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
                String url = textField_ip.getText()+"/sealCenter/entities/v1.0/sealData";

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

                String oid = SM2signatureAlgorithm.toString();
                param = param + "&"+"signMethod=" + oid; // TODO: to integer

                if(textField_cert.getText().length()<1){
                    JOptionPane.showMessageDialog(null, "signer cert is missing");
                    return;
                }

                try {
                    byte[] cert = PDFUtils.getBytesFromFile(textField_cert.getText());
                    String s = new String(cert);
                    param = param + "&"+"Cert=" + s;
                } catch (IOException e1) {
                    e1.printStackTrace();
                    JOptionPane.showMessageDialog(null, "something wrong with signer cert 's reading");
                    return;
                }

                if(total == null){
                    JOptionPane.showMessageDialog(null, "invalid pdf file");
                    return;
                }

                String base64encodedString = getEncoder().encodeToString(total);
                int length = total.length;
                param = param + "&"+"inDataLen=" + length + "&"+"inData=" + base64encodedString;

                String result = HttpUtils.sendPost(url,param);

                //TODO : process result
                //byte[] base64decodedBytes = Base64.getDecoder().decode(base64encodedString);

            }
        });
        button_verify.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String url = textField_ip.getText()+"/sealCenter/entities/v1.0/verifysealData";
                super.mouseClicked(e);
            }
        });
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("esealClinet");
        frame.setContentPane(new esealClinet().client);
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


    private static byte[] calSM3Digest(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.reset();
        digest.update(data, 0, data.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        digest.doFinal(resBuf, 0);
        return resBuf;
    }
}
