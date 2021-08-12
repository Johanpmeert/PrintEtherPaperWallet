package com.johanpmeert;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import javax.swing.*;
import java.awt.image.BufferedImage;
import java.awt.print.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class Main implements Printable, ActionListener {

    private static String hexRandom, qrCodePrivate, qrCodeETH;
    private static JLabel hexRandomValueLabel, PrivateValueLabel, EthAddressValueLabel;

    private enum Actions {
        PRINT, REGENERATE, QUIT, COPYPRIVATE, COPYETH
    }

    public static void main(String[] args) {
        // bitcoin address generation
        generateBitcoinAddresses();
        // Create UI
        UIManager.put("swing.boldMetal", Boolean.FALSE);
        JFrame f = new JFrame("Ethereum paper wallet printer using SecureRandom, EIP-55 format");
        f.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
        f.setSize(750, 200);
        // Create buttons
        JButton printButton = new JButton("Print paper wallet");
        printButton.setBounds(10, 120, 150, 30);
        printButton.addActionListener(new Main());
        printButton.setActionCommand(Actions.PRINT.name());
        f.add(printButton);
        JButton regenerateButton = new JButton("Regenerate keys");
        regenerateButton.setBounds(200, 120, 150, 30);
        regenerateButton.addActionListener(new Main());
        regenerateButton.setActionCommand(Actions.REGENERATE.name());
        f.add(regenerateButton);
        JButton quitButton = new JButton("Quit");
        quitButton.setBounds(400, 120, 100, 30);
        quitButton.addActionListener(new Main());
        quitButton.setActionCommand(Actions.QUIT.name());
        f.add(quitButton);
        JButton copyWifButton = new JButton("COPY");
        copyWifButton.setBounds(625, 40, 75, 25);
        copyWifButton.addActionListener(new Main());
        copyWifButton.setActionCommand(Actions.COPYPRIVATE.name());
        f.add(copyWifButton);
        JButton copyBtcButton = new JButton("COPY");
        copyBtcButton.setBounds(625, 70, 75, 25);
        copyBtcButton.addActionListener(new Main());
        copyBtcButton.setActionCommand(Actions.COPYETH.name());
        f.add(copyBtcButton);
        // Create Text labels
        JLabel hexRandomLabel = new JLabel("Hex random seed:");
        hexRandomLabel.setBounds(10, 10, 100, 20);
        f.add(hexRandomLabel);
        hexRandomValueLabel = new JLabel(hexRandom);
        hexRandomValueLabel.setBounds(115, 10, 500, 20);
        f.add(hexRandomValueLabel);
        JLabel PrivLabel = new JLabel("Ether private key:");
        PrivLabel.setBounds(10, 40, 140, 20);
        f.add(PrivLabel);
        PrivateValueLabel = new JLabel(qrCodePrivate);
        PrivateValueLabel.setBounds(115, 40, 500, 20);
        f.add(PrivateValueLabel);
        JLabel EthAddressLabel = new JLabel("Ethereum address (EIP-55):");
        EthAddressLabel.setBounds(10, 70, 150, 20);
        f.add(EthAddressLabel);
        EthAddressValueLabel = new JLabel(qrCodeETH);
        EthAddressValueLabel.setBounds(170, 70, 400, 20);
        f.add(EthAddressValueLabel);
        // Finalize layout
        f.setLayout(null);
        f.setVisible(true);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals(Actions.PRINT.name())) {
            PrinterJob job = PrinterJob.getPrinterJob();
            job.setPrintable(this);
            boolean ok = job.printDialog();
            if (ok) {
                try {
                    job.print();
                } catch (PrinterException ex) {
                    ex.printStackTrace();
                }
            }
        } else if (e.getActionCommand().equals(Actions.REGENERATE.name())) {
            generateBitcoinAddresses();
            updateLabels();
        } else if (e.getActionCommand().equals(Actions.QUIT.name())) {
            System.exit(0);
        } else if (e.getActionCommand().equals(Actions.COPYPRIVATE.name())) {
            StringSelection sS = new StringSelection(qrCodePrivate);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(sS, null);
        } else if (e.getActionCommand().equals(Actions.COPYETH.name())) {
            StringSelection sS = new StringSelection(qrCodeETH);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(sS, null);
        }
    }

    public static void generateBitcoinAddresses() {
        // Keccak integrity test
        Keccak.Digest256 kcc = new Keccak.Digest256();
        byte[] digest = kcc.digest("".getBytes(StandardCharsets.UTF_8));
        String kcctest = "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470";
        System.out.print("\nKeccak-256 testhash of \"\" = " + byteArrayToHexString(digest) + ", should be " + kcctest);
        if (byteArrayToHexString(digest).equals(kcctest)) {
            System.out.println(" ... test SUCCESFULL");
        } else {
            System.out.println(" ... test FAILED");
            System.out.println("Keccak-256 algorithm not compatible on this system/OS/JVM");
            System.exit(0);
        }
        //
        final String upperLimit = "F".repeat(56);  // safe upper limit for validity of ECDSA
        byte[] random32bytes = new byte[32];
        SecureRandom sr = new SecureRandom();  // using cryptographic safe random function
        do {
            sr.nextBytes(random32bytes);
            hexRandom = byteArrayToHexString(random32bytes);
        }
        while (hexRandom.substring(0, 55).equals(upperLimit));
        qrCodePrivate = hexRandom;
        String publicKey = privToPublic(hexRandom).substring(2); // lose the 04 in front
        String rawEther = byteArrayToHexString(kcc.digest(hexStringToByteArray(publicKey)));
        String etherAddr = "0x" + rawEther.substring(rawEther.length() - 40).toLowerCase();
        String letters = "abcdef";
        String letters2 = "89abcdef";
        String eip1 = etherAddr.substring(2); // get rid of the 0x
        String eip2 = byteArrayToHexString(kcc.digest(eip1.getBytes())).toLowerCase(); // it's the lowercase string of the address to hash so we use .getBytes(), not the bytearray conversion
        for (int teller = 0; teller < eip1.length(); teller++) {
            if (letters.contains(eip1.substring(teller, teller + 1))) {  // if the character we look at is a letter
                if (letters2.contains(eip2.substring(teller, teller + 1))) {  // and the corresponding character in the hash string is 8, 9, a, b, c, d, e or f
                    eip1 = eip1.substring(0, teller) + eip1.substring(teller, teller + 1).toUpperCase(Locale.ROOT) + eip1.substring(teller + 1);  // then we need to capitalise this letter
                }
            }
        }
        qrCodeETH = "0x" + eip1;  // re-add the 0x in front
    }

    public static void updateLabels() {
        hexRandomValueLabel.setText(hexRandom);
        PrivateValueLabel.setText(qrCodePrivate);
        EthAddressValueLabel.setText(qrCodeETH);
    }

    public int print(Graphics g, PageFormat pf, int page) {
        if (page > 1) {
            return NO_SUCH_PAGE;
        }
        // Page 1
        if (page == 0) {
            Graphics2D g2d = (Graphics2D) g;
            g.setFont(new Font("Monospaced", Font.PLAIN, 8));
            g2d.translate(pf.getImageableX(), pf.getImageableY());
            BufferedImage QRimagePriv = null, QRimageETH = null, RandomImage1 = null, RandomImage2 = null;
            try {
                QRimagePriv = createQRImage(qrCodePrivate, 120);
                QRimageETH = createQRImage(qrCodeETH, 120);
                RandomImage1 = createRandomImage(125, 150);
                RandomImage2 = createRandomImage(100);
            } catch (WriterException e) {
                e.printStackTrace();
            }
            g.drawImage(QRimageETH, 20, 50, 110, 110, null);
            g.drawString("ETH ADDRESS", 45, 150);
            g.setFont(new Font("Monospaced", Font.PLAIN, 6));
            g.drawString(qrCodeETH, 5, 45);
            g.drawString(qrCodeETH, 5, 165);
            g.drawImage(RandomImage1, 190, 30, 125, 150, null);
            g.drawImage(RandomImage2, 355, 55, 100, 100, null);
            g.drawImage(QRimagePriv, 460, 45, 120, 120, null);
            g.drawString(qrCodePrivate, 330, 50);
            g.drawString(qrCodePrivate, 330, 165);
            g.drawLine(0, 10, 325, 10);
            g.drawLine(325, 10, 335, 30);
            g.drawLine(335, 30, 570, 30);
            g.drawLine(0, 200, 325, 200);
            g.drawLine(325, 200, 335, 180);
            g.drawLine(335, 180, 570, 180);
            g.drawLine(340, 60, 340, 145);
            g.drawLine(185, 20, 185, 190);
        }
        if (page == 1) {
            Graphics2D g2d = (Graphics2D) g;
            g.setFont(new Font("Monospaced", Font.PLAIN, 8));
            g2d.translate(pf.getImageableX(), pf.getImageableY());
            BufferedImage RandomRect = null;
            try {
                RandomRect = createRandomImage(120, 20);
            } catch (WriterException e) {
                e.printStackTrace();
            }
            g.drawLine(260, 10, 570, 10);
            g.drawLine(260, 200, 570, 200);
            g.drawLine(260, 10, 260, 200);
            g.drawLine(570, 10, 570, 200);
            g.drawLine(300, 80, 530, 80);
            g.drawLine(300, 130, 530, 130);
            g.drawLine(300, 180, 530, 180);
            g.drawString("Private key", 150, 80);
            g.drawString("inside here", 150, 100);
            g.setFont(new Font("Monospaced", Font.BOLD, 10));
            g.drawString("KEEP HIDDEN", 140, 140);
            g.drawString("ETHEREUM PAPER WALLET (EIP-55)", 325, 30);
            g.drawImage(RandomRect, 120, 40, 120, 20, null);
            g.drawImage(RandomRect, 120, 155, 120, 20, null);
        }
        return PAGE_EXISTS;
    }

    private static BufferedImage createQRImage(String qrCodeText, int size) throws WriterException {
        Hashtable<EncodeHintType, ErrorCorrectionLevel> hintMap = new Hashtable<>();
        hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H);
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix byteMatrix = qrCodeWriter.encode(qrCodeText, BarcodeFormat.QR_CODE, size, size, hintMap);
        int matrixSize = byteMatrix.getWidth();
        BufferedImage image = new BufferedImage(matrixSize, matrixSize, BufferedImage.TYPE_INT_RGB);
        image.createGraphics();
        Graphics2D graphics = (Graphics2D) image.getGraphics();
        graphics.setColor(Color.WHITE);
        graphics.fillRect(0, 0, matrixSize, matrixSize);
        graphics.setColor(Color.BLACK);
        for (int i = 0; i < matrixSize; i++) {
            for (int j = 0; j < matrixSize; j++) {
                if (byteMatrix.get(i, j)) {
                    graphics.fillRect(i, j, 1, 1);
                }
            }
        }
        return image;
    }

    private static BufferedImage createRandomImage(int size) throws WriterException {
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_RGB);
        image.createGraphics();
        Graphics2D graphics = (Graphics2D) image.getGraphics();
        graphics.setColor(Color.WHITE);
        graphics.fillRect(0, 0, size, size);
        graphics.setColor(Color.BLACK);
        SecureRandom sr = new SecureRandom();
        for (int i = 0; i < size; i++) {
            for (int j = 0; j < size; j++) {
                if (sr.nextBoolean()) {
                    graphics.fillRect(i, j, 1, 1);
                }
            }
        }
        return image;
    }

    private static BufferedImage createRandomImage(int size1, int size2) throws WriterException {
        BufferedImage image = new BufferedImage(size1, size2, BufferedImage.TYPE_INT_RGB);
        image.createGraphics();
        Graphics2D graphics = (Graphics2D) image.getGraphics();
        graphics.setColor(Color.WHITE);
        graphics.fillRect(0, 0, size1, size2);
        graphics.setColor(Color.BLACK);
        SecureRandom sr = new SecureRandom();
        for (int i = 0; i < size1; i++) {
            for (int j = 0; j < size2; j++) {
                if (sr.nextBoolean()) {
                    graphics.fillRect(i, j, 1, 1);
                }
            }
        }
        return image;
    }

    public static byte[] privToPublic(byte[] address) {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        org.bouncycastle.math.ec.ECPoint pointQ = spec.getG().multiply(new BigInteger(1, address));
        return pointQ.getEncoded(false);
    }

    public static String privToPublic(String address) {
        return byteArrayToHexString(privToPublic(hexStringToByteArray(address)));
    }

    private static byte[] hexStringToByteArray(String hex) {
        hex = hex.length() % 2 != 0 ? "0" + hex : hex;
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    private static String byteArrayToHexString(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}