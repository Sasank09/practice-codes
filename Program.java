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

public class Program
{
    public static final int AES_KEY_SIZE = 32;
    public static final int GCM_IV_LENGTH = 12;// 4 for counter
    public static final int GCM_TAG_LENGTH = 16;
    public static final byte[] aad = "1234abcd".getBytes();  // authenticated data
    
    static byte[] iv= new SecureRandom().generateSeed(GCM_IV_LENGTH);
//GENERATING EC KEYS//
    public static KeyPair generateECKeys(String secretekey)
    {

        KeyPair kpU = null;
        try
        {
            KeyPairGenerator kpg;
            kpg = KeyPairGenerator.getInstance("EC", "SunEC");
            ECGenParameterSpec ecsp;
            ecsp = new ECGenParameterSpec(secretekey);
            kpg.initialize(ecsp);
            kpU = kpg.genKeyPair();

        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        return kpU;

    }
//ENCRYPTION METHOD//
    public static String encryptString(SecretKey encryptionKey, String plainText) throws Exception 
    {       
        byte[] plainTextBytes = plainText.getBytes("UTF-8");
        byte[] cipherText;

        //Key encryptionKey = new SecretKeySpec(key.getEncoded(),key.getAlgorithm()); // get the key in aes format
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8,iv);
        
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
        byte[] cipherTextBytes = hexToBytes(cipherText);
        byte[] plainText;
        //Key decryptionKey = new SecretKeySpec(key.getEncoded(),key.getAlgorithm());
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");     

        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, gcmParameterSpec);
        cipher.updateAAD(aad);
        plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
        int decryptLength = cipher.update(cipherTextBytes, 0, cipherTextBytes.length, plainText, 0);
        decryptLength += cipher.doFinal(plainText, decryptLength);

        return new String(plainText,"UTF-8");
    }
 //Conversions//
    public static String bytesToHex(byte[] data) 
    {   
        int length= data.length;
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

    public static byte[] hexToBytes(String string) 
    {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) 
        {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character.digit(string.charAt(i + 1), 16));
        }
        return data;
    }

//MAIN METHOD//
    public static void main(String[] args)throws Exception 
    {
        double startf=System.currentTimeMillis();
       
        Program program = new Program();
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
       
        System.out.println("\n---------------------------USER 1---------------------------------------------------------\n");
        
        double startp = System.currentTimeMillis(); 
        KeyPair U1 = generateECKeys("secp256k1");
        PrivateKey privKeyU = U1.getPrivate();
        PublicKey pubKeyU = U1.getPublic();
        double endp = System.currentTimeMillis();     
        System.out.println("User 1: PrivateKey :  " + bytesToHex(privKeyU.getEncoded()));
        System.out.println("User 1: PublicKey  :  " + pubKeyU.toString());

        System.out.println("\n---------------------------------OTHER END USER 2------------------------------------------\n");
     
        KeyPair U2 = generateECKeys("secp256k1");
        PrivateKey privKeyV = U2.getPrivate();
        PublicKey pubKeyV = U2.getPublic();
        System.out.println("\nUSER 2 PrivateKey : "+bytesToHex(privKeyV.getEncoded()));
        System.out.println("User 2 PublicKey  : " + pubKeyV.toString());

        System.out.println("\n--------------------------------SECRET KEY GENERATION---------------------------------------\n");
            
        double startk = System.currentTimeMillis();
        KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
        ecdhV.init(privKeyV);
        ecdhV.doPhase(pubKeyU,true);
        byte[] data2 = ecdhV.generateSecret();
        SecretKey key2 = new SecretKeySpec(data2, 0, AES_KEY_SIZE, "AES");
        double endk = System.currentTimeMillis(); 
            
  		KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
        ecdhU.init(privKeyU);
        ecdhU.doPhase(pubKeyV,true);
        byte[] data1 =  ecdhU.generateSecret();
        SecretKey key1 = new SecretKeySpec(data1, 0, AES_KEY_SIZE, "AES");
   
        System.out.println("\nSecret computed by User2: 0x" +bytesToHex(data2));
        System.out.println("\nSecret computed by User1: 0x" +bytesToHex(data1));

        System.out.println("\n--------------------------------ENTER MESSAGE---------------------------------------\n");
        System.out.print("Getting Input From File input.txt  :::  \n\n");
        String in =keyRead.readLine();
        FileReader fr=new FileReader(".\\"+in+".txt");    
      	BufferedReader br=new BufferedReader(fr);    
        int i;    
        StringBuffer inp = new StringBuffer();
        while((i=br.read())!=-1)
        {
          	inp.append((char)i);  
        }  
        System.out.println(inp);
        br.close();    
        fr.close(); 
        String str = inp.toString();

        System.out.println("\n--------------------------------CIPHER TEXT---------------------------------------\n");
        double starte = System.currentTimeMillis();
        String encryptedmsg = encryptString(key1,str);
        double ende = System.currentTimeMillis();  
        System.out.println("Sending EncryptedText to File encrypted.txt  :::  \n\n"+encryptedmsg);
    
        OutputStream outputStream = new FileOutputStream(".\\encrypted.txt");  
        Writer outputStreamWriter = new OutputStreamWriter(outputStream);  
  
        outputStreamWriter.write(encryptedmsg);    
        outputStreamWriter.close(); 

        System.out.println("\n--------------------------------PLAIN TEXT---------------------------------------\n");
        double startd = System.currentTimeMillis();
        String decryptedmsg =decryptString(key2,encryptedmsg);
        double endd = System.currentTimeMillis(); 
        System.out.println("Sending DecryptedText to File decrypted.txt  :::  \n\n"+decryptedmsg);

        outputStream = new FileOutputStream(".\\decrypted.txt");   
  		outputStreamWriter = new OutputStreamWriter(outputStream);
        outputStreamWriter.write(decryptedmsg);    
        outputStreamWriter.close(); 
        outputStream.close();
        double endf=System.currentTimeMillis();
   		
        System.out.println("\n---------------------------------------------------------------------------------");
        if(str.equals(decryptedmsg))
        {
           	System.out.println("\tAlgorithm is Successfully Executed");
        }
        else{ System.out.println("\tSomething Wrong with Encryption and Decrytption");}
           
       System.out.println("----------------------------------STATUS------------------------------------------");
            
            double inpFilesize =str.getBytes().length;
            double encFilesize =encryptedmsg.getBytes().length;
            double decFilesize =decryptedmsg.getBytes().length;
            System.out.println("\n\tINPUT FILE SIZE         :::: "+inpFilesize+" Bytes");
            System.out.println("\tENCRYPTED FILE SIZE     :::: "+encFilesize+" Bytes");
            System.out.println("\tDECRYPTED FILE SIZE     :::: "+decFilesize+" Bytes");
            System.out.println("\n\tTime Taken for KeyPairGen   ::   " +(endp - startp) + " ms");
            System.out.println("\tTime Taken for SecretKeyGen ::   " +(endk - startk) + " ms");
            System.out.println("\tTime Taken for Encryption   ::   " +(ende - starte) + " ms");
     	    System.out.println("\tTime Taken for Decryption   ::   " +(endd - startd) + " ms");
   	        System.out.println("\tTotal Time Taken for Algo   ::   " +(endp+ende+endd+endk - startp-startk-starte-startd) + " ms");
   		    System.out.println("\tTime Taken for Execution    ::   " +(endf - startf) + " ms");
			System.out.println("\n-------------------------------**********---------------------------------------\n");
     }
}