package com;
import java.math.BigInteger;
import java.util.Random;
import java.io.Serializable;
import java.io.FileInputStream;
import java.util.ArrayList;
public class ECC implements Serializable{
	// Parts of one ECC system.
	EllipticCurve curve;
	Point generator;
	Point publicKey;
	BigInteger privateKey;
	
public Point[] encrypt(Point plain) {
	// First we must pick a random k, in range.
	int bits = curve.getP().bitLength();
	BigInteger k = new BigInteger(bits, new Random());
	System.out.println("Picked "+k+" as k for encrypting.");
	// Our output is an ordered pair, (k*generator, plain + k*publickey)
	Point[] ans = new Point[2];
	ans[0] = generator.multiply(k);
	ans[1] = plain.add(publicKey.multiply(k));
	return ans;
}
// Decryption - notice the similarity to El Gamal!!!
public Point decrypt(Point[] cipher) {
	// This is what we subtract out.
	Point sub = cipher[0].multiply(privateKey);
	// Subtract out and return.
	return cipher[1].subtract(sub);
}
public String toString() {
	return "Gen: "+generator+"\n"+"pri: "+privateKey+"\n"+"pub: "+publicKey;
}
public String loadKeys(String id,String random,String pk){
	// Just use the book's curve and test.
	BigInteger bi = new BigInteger("6603472258910975390409386875419060670912711158650902673593472681492443618519247014208029797276135537622513121022070188456656102492281101483976551651052349400660865106891558505875353446226922766370854915854192720967802181687778812897356989588519483299949526013215505901680565031499772113902446208729069");
	curve = new EllipticCurve(bi,bi,bi);
	BigInteger x = new BigInteger(id);
	BigInteger y = new BigInteger(random);
	BigInteger nA = new BigInteger(pk);
	generator = new Point(curve, x, y);
	privateKey = nA;
	publicKey = generator.multiply(privateKey);
	return publicKey.toString();
}
public ECC getKeys(){
	return this;
}
/*public static void main(String args[])throws Exception{
	//BigInteger prime = BigInteger.probablePrime(1000,new Random());
	//System.out.println(prime+"\n\n");
	FileInputStream fin = new FileInputStream("tt.txt");
	byte b[] = new byte[fin.available()];
	fin.read(b,0,b.length);
	fin.close();
	ECC ecc = new ECC();
	String bi = "1235";//"14893003337626352152463254152616458181260144281";
	ecc.loadKeys(bi,bi,bi);
	String data = new String(b);
	String arr[] = data.split("\n");
	ArrayList<Point[]> list = new ArrayList<Point[]>();
	for(int i=0;i<arr.length;i++) {
		Point plain = new Point(ecc.curve, new BigInteger(arr[i].getBytes()), new BigInteger("kk".getBytes()));
		Point[] cipher = ecc.getKeys().encrypt(plain);
		list.add(cipher);
		System.out.println(i);
		
	}
	StringBuilder sb = new StringBuilder();
	for(int i=0;i<list.size();i++){
		Point decrypt = ecc.getKeys().decrypt(list.get(i));
		byte b1[] = decrypt.getX().toByteArray();
		byte b2[] = decrypt.getY().toByteArray();
		System.out.println("value = "+new String(b1)+" "+new String(b2));
	}
	System.out.println(ecc.toString());
}*/
}