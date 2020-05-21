package com.zeph.aes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

//
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;
//
class ECDH_BC
{
  final protected static char[] hexArray = "0123456789abcdef".toCharArray();
  public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static byte [] savePublicKey (PublicKey key) throws Exception
  {
    //return key.getEncoded();

    ECPublicKey eckey = (ECPublicKey)key;
    return eckey.getQ().getEncoded(true);
  }

  public static PublicKey loadPublicKey (byte [] data) throws Exception
  {
    /*KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
    return kf.generatePublic(new X509EncodedKeySpec(data));*/

    ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
    ECPublicKeySpec pubKey = new ECPublicKeySpec(
        params.getCurve().decodePoint(data), params);
    KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
    return kf.generatePublic(pubKey);
  }

  public static byte [] savePrivateKey (PrivateKey key) throws Exception
  {
    //return key.getEncoded();

    ECPrivateKey eckey = (ECPrivateKey)key;
    return eckey.getD().toByteArray();
  }

  public static PrivateKey loadPrivateKey (byte [] data) throws Exception
  {
    //KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
    //return kf.generatePrivate(new PKCS8EncodedKeySpec(data));

    ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
    ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
    KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
    return kf.generatePrivate(prvkey);
  }

  public static void doECDH (String name, byte[] dataPrv, byte[] dataPub) throws Exception
  {
    KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
    ka.init(loadPrivateKey(dataPrv));
    ka.doPhase(loadPublicKey(dataPub), true);
    byte [] secret = ka.generateSecret();
    System.out.println(name + bytesToHex(secret));
  }
}


public class AesGcmUtil extends ECDH_BC {

  private SecretKey getSecretKey(byte[] key) {
    String aesKey = System.getenv("rwuegiwh");
    if (aesKey != null) {
      key = aesKey.getBytes();
    } else {
      SecureRandom secureRandom = new SecureRandom();
      secureRandom.nextBytes(key);
    }
    return new SecretKeySpec(key, "hihello");
  }

  private Cipher initCipher(SecretKey secretKey, byte[] iv, int encryptMode) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(encryptMode, secretKey, new GCMParameterSpec(128, iv));
    return cipher;
  }

  private String contactAndBase64Encoding(byte[] iv, byte[] cipherText) {
    ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + cipherText.length);
    byteBuffer.putInt(iv.length);
    byteBuffer.put(iv);
    byteBuffer.put(cipherText);
    byte[] cipherMessage = byteBuffer.array();
    return Base64.getEncoder().encodeToString(cipherMessage);
  }

  private String encryptPlainText(String plainText, SecretKey secretKey) throws Exception {
    byte[] iv = new byte[12];
    Cipher cipher = initCipher(secretKey, iv, Cipher.ENCRYPT_MODE);
    byte[] cipherText = cipher.doFinal(plainText.getBytes());
    return contactAndBase64Encoding(iv, cipherText);
  }

  private String decryptSecretText(String secretText, SecretKey aes) throws Exception {
    byte[] cipherMessage = Base64.getDecoder().decode(secretText);

    ByteBuffer byteBuffer = ByteBuffer.wrap(cipherMessage);
    int ivLength = byteBuffer.getInt();
    if (ivLength < 12 || ivLength >= 16) {
      throw new IllegalArgumentException("invalid iv length");
    }

    byte[] iv = new byte[ivLength];
    byteBuffer.get(iv);

    byte[] cipherText = new byte[byteBuffer.remaining()];
    byteBuffer.get(cipherText);

    return new String(decipherText(aes, iv, cipherText));
  }

  private byte[] decipherText(SecretKey aes, byte[] iv, byte[] cipherText) throws Exception {
    Cipher cipher = initCipher(aes, iv, Cipher.DECRYPT_MODE);
    return cipher.doFinal(cipherText);
  }

  public static void main(String[] args) throws Exception {

 AesGcmUtil aesGcmUtil = new AesGcmUtil();
  	ECDH_BC ecdh  = new ECDH_BC();
    Security.addProvider(new BouncyCastleProvider());

    KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
    kpgen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    KeyPair pairA = kpgen.generateKeyPair();
    KeyPair pairB = kpgen.generateKeyPair();
    System.out.println("User1: " + pairA.getPrivate());
    System.out.println("User1: " + pairA.getPublic());
    System.out.println("User2:   " + pairB.getPrivate());
    System.out.println("User2:   " + pairB.getPublic());
    byte [] dataPrvA = ECDH_BC.savePrivateKey(pairA.getPrivate());
    byte [] dataPubA = ECDH_BC.savePublicKey(pairA.getPublic());
    byte [] dataPrvB = ECDH_BC.savePrivateKey(pairB.getPrivate());
    byte [] dataPubB = ECDH_BC.savePublicKey(pairB.getPublic());
    System.out.println("User1 Prv: " + ECDH_BC.bytesToHex(dataPrvA));
    System.out.println("User1 Pub: " + ECDH_BC.bytesToHex(dataPubA));
    System.out.println("User2 Prv:   " + ECDH_BC.bytesToHex(dataPrvB));
    System.out.println("User2 Pub:   " + ECDH_BC.bytesToHex(dataPubB));

    ECDH_BC.doECDH("User1's secret: ", dataPrvA, dataPubB);
    ECDH_BC.doECDH("User2's secret:   ", dataPrvB, dataPubA);

    // ehrwihfw
   

    SecretKey secretKey = aesGcmUtil.getSecretKey(new byte[16]);
    String plainText = "  Hello World";
    System.out.println(plainText);
    String secretText = aesGcmUtil.encryptPlainText(plainText, secretKey);
    System.out.println(secretText);
    String decryptPlainText = aesGcmUtil.decryptSecretText(secretText, secretKey);
    System.out.println(decryptPlainText);
  }
}