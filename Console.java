import java.io.*;
import java.util.Scanner;
import java.math.BigInteger;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Console 
{

    public static final int AES_KEY_SIZE = 32;  //bytes
    public static final int GCM_IV_LENGTH = 12;// 4 for counter
    public static final int GCM_TAG_LENGTH = 16;
    public static final byte[] aad = "1234abcd".getBytes();
    
    static byte[] iv= new SecureRandom().generateSeed(GCM_IV_LENGTH);
                          
//GENERATING EC KEYS//
    public static KeyPair generateECKeys(String curve)
    {

        KeyPair kpU = null;
        try {
            KeyPairGenerator kpg;
            kpg = KeyPairGenerator.getInstance("EC", "SunEC");
            ECGenParameterSpec ecsp;
            //String parameter = "sect113r2";
            ecsp = new ECGenParameterSpec(curve);
            kpg.initialize(ecsp);
            kpU = kpg.genKeyPair();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return kpU;

    }
//ENCRYPTION METHOD//
    public static String encryptString(SecretKey encryptionKey, String plainText) throws Exception 
    {
            //Key encryptionKey = new SecretKeySpec(key.getEncoded(),0,32,key.getAlgorithm());
            //System.out.println("Algorithm Used For Encryption"+key.getAlgorithm());
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8,iv);
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] cipherText;

            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, gcmParameterSpec);
            cipher.updateAAD(aad);
            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
            int encryptLength = cipher.update(plainTextBytes, 0,plainTextBytes.length, cipherText, 0);
            encryptLength += cipher.doFinal(cipherText, encryptLength);

            return bytesToHex(cipherText);
    }
//DECRYPTION METHOD//
    public static String decryptString(SecretKey decryptionKey, String cipherText)throws Exception 
    {
            //Key decryptionKey = new SecretKeySpec(key.getEncoded(),0,AES_KEY_SIZE,key.getAlgorithm());
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] cipherTextBytes = hexToBytes(cipherText);
            byte[] plainText;

            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, gcmParameterSpec);
            cipher.updateAAD(aad);  // authenticated data
            plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
            int decryptLength = cipher.update(cipherTextBytes, 0, cipherTextBytes.length, plainText, 0);
            decryptLength += cipher.doFinal(plainText, decryptLength);

            return new String(plainText, "UTF-8");
    }
//Conversions//
    public static String bytesToHex(byte[] data, int length) 
    {

        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++)
         {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
         }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data)
    {
        return bytesToHex(data, data.length);
    }
    public static byte[] hexToBytes(String string) 
    {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) 
        {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
                    .digit(string.charAt(i + 1), 16));
        }
        return data;
    }
//MAIN METHOD//
    public static void main(String[] args)throws Exception 
    {
    	long startf=System.currentTimeMillis();
    	Console ECC = new Console();
     
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
			     		
		    long startp = System.currentTimeMillis();
            KeyPair U1 = generateECKeys("secp256k1");
            PrivateKey privKeyU = U1.getPrivate();
            PublicKey pubKeyU = U1.getPublic();
            long endp = System.currentTimeMillis();

            KeyPair U2 = generateECKeys("secp256k1");
		    PrivateKey privKeyV = U2.getPrivate();
		    PublicKey pubKeyV = U2.getPublic();
		    

		    System.out.println("\n--------------------------------SECRET KEY GENERATION---------------------------------------\n");        
            
            long startk = System.currentTimeMillis();
            KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
            ecdhU.init(privKeyU);
            ecdhU.doPhase(pubKeyV,true);
            byte[] data1 =  ecdhU.generateSecret();
            SecretKey key1 = new SecretKeySpec(data1, 0,AES_KEY_SIZE,"AES");
            long endk = System.currentTimeMillis();
            
            KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
            ecdhV.init(privKeyV);
            ecdhV.doPhase(pubKeyU,true);
  			byte[] data2 = ecdhV.generateSecret();
            SecretKey key2 = new SecretKeySpec(data2, 0,AES_KEY_SIZE, "AES");

            System.out.println("\nSecret computed by User1: 0x" +bytesToHex(key1.getEncoded()));
            System.out.println("\nSecret computed by User2: 0x" +bytesToHex(key2.getEncoded()));
       
    		System.out.println("\n--------------------------------ENTER MESSAGE---------------------------------------\n");

            System.out.print("Getting  input ::: PLAIN TEXT  :::  ");
            String str =keyRead.readLine();

     		System.out.println("\n--------------------------------CIPHER TEXT---------------------------------------\n");

            long starte = System.currentTimeMillis();
            String encryptedmsg = encryptString(key1,str);
            long ende = System.currentTimeMillis();  

            System.out.println("EncryptedText  :::  "+encryptedmsg);
    
            System.out.println("\n--------------------------------PLAIN TEXT---------------------------------------\n");

            long startd = System.currentTimeMillis();
            String decryptedmsg =decryptString(key2,encryptedmsg);
            long endd = System.currentTimeMillis(); 

            System.out.println("\nDecryptedText :::  "+decryptedmsg);

            long endf=System.currentTimeMillis();
        
      		System.out.println("\n---------------------------------------------------------------------------------\n");

            	if(str.equals(decryptedmsg))
            	{
                	System.out.println("\n\tAlgorithm is Successfully Executed");
            	}
            	else
            	{
            		 System.out.println("\n\tSomething Wrong with Encryption and Decrytption");
            		 System.exit(0);
            	}
           
      		System.out.println("\n----------------------------------STATUS------------------------------------------\n");
            
             double inpFilesize =str.getBytes().length;
             double encFilesize =encryptedmsg.getBytes().length;
             double decFilesize =decryptedmsg.getBytes().length;
             System.out.println("\tINPUT  SIZE       :::: "+inpFilesize+" Bytes");
             System.out.println("\tENCRYPTED FILE SIZE   :::: "+encFilesize+" Bytes");
             System.out.println("\tDECRYPTED FILE SIZE   :::: "+decFilesize+" Bytes");
             System.out.println("\tTime Taken for SecretKeyGen ::   " +(endk - startk) + " ms");
             System.out.println("\tTime Taken for Encryption   ::   " +(ende - starte) + " ms");
             System.out.println("\tTime Taken for Decryption   ::   " +(endd - startd) + " ms");
             System.out.println("\tTotal Time Taken for Algo   ::   " +(endp+ende+endd+endk - startp-startk-starte-startd) + " ms");
             System.out.println("\tTime Taken for ConsoleExecution    ::   " +(endf - startf) + " ms");
             System.out.println("\n-------------------------------**********---------------------------------------\n");
             
     }
}