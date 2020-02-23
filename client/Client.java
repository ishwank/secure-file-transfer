import java.net.*; 
import java.io.*; 
import javax.crypto.*;
import java.math.*;
import java.sql.Timestamp;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.nio.file.Files;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Random;
import java.net.*;
import java.security.SignatureException;
import java.util.Formatter;
import javax.crypto.Mac;
import java.nio.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import java.io.DataOutputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class Client 
{


    private static Cipher encryptCipher;
	private static Cipher decryptCipher;
    private byte[] serverHelloMessage;
  //  private SecretKey key;
    private byte[] helloNonce;
    private byte[] askForCertNonce;
	private static Socket socket,socket1;
    private byte[] fileToSend;
  //  private static Key serverPublicKey;
	
	static long  P, G, x, a, y, b, ka, kb,fileSize;
	static long leftLimit = 1000000000000000L;
	static long rightLimit = 9999999999999999L;
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static String key = "12345678910";
	private static final String IV = "ThisIsFirstPacket";
	static int packetsize=1024;
	static double nosofpackets;
	
    public static void main (String [] args ) throws IOException,FileNotFoundException,Exception 
    {
	   
		System.out.println("Start"); 
	    int bytesRead;
	    int currentTot = 0; 
	
	   while(true)
       {
		socket = new Socket("localhost",6000);
	//	System.out.println("Connection made");
		
        System.out.println("\n1. Download\n2. Upload\n3. Receive certificate\n4. Generate key \n5. Quit\n");
        Scanner sc = new Scanner(System.in);
        int choice=sc.nextInt();
        OutputStream os = null;
        os= socket.getOutputStream();
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeUTF(String.valueOf(choice));
		
		//1. download 2. upload 3. get certificate 4. get keys 5. exit
			switch(choice)
			{
				case 1:
				key = String.valueOf(kb);
				String plainregained = "";
				int count;
				byte[] buffer = new byte[8192];
				FileOutputStream fos = new FileOutputStream("copy.txt");
				BufferedOutputStream bos = new BufferedOutputStream(fos);
				InputStream is1 = socket.getInputStream();
				DataInputStream bis = new DataInputStream(is1);
				String temp = bis.readUTF();
				fileSize = Long.valueOf(temp);
				nosofpackets=Math.ceil(((int) fileSize)/packetsize);
				
				for(double i=0;i<nosofpackets+1;i++)
				{
					InputStream is = socket.getInputStream();
					byte[] mybytearray = new byte[packetsize];
					bytesRead = is.read(mybytearray, 0,mybytearray.length );
				//	System.out.println("Packet:"+(i+1));
					
					int[] toCalculate = convertToIntArray(mybytearray);
					String temp1 = new String(mybytearray);
				
					if(i == 0)
					{
						String b_i = calculateRFC2104HMAC(IV,key);
						plainregained = reversexor(toCalculate,b_i);
					}
					
					else
					{
						String b_i = calculateRFC2104HMAC(Arrays.toString(toCalculate).replace("[","").replace("]","").replace(",",""),key);
						plainregained = reversexor(toCalculate,b_i);
					}
					
					byte[] bytearray = plainregained.getBytes();
				
					bos.write(bytearray, 0,bytearray.length);
				}
				Thread.sleep(4000);	
				socket.close();
				bos.close();		
				System.out.println("File successfully downloaded");			
				break;
				
				case 2:
					key = String.valueOf(kb);
					File myFile = new File("sendfile.txt");
					fileSize = myFile.length();
				//	System.out.println("filesize"+ fileSize);
					nosofpackets=Math.ceil(((int) myFile.length())/packetsize);
					//System.out.println("nosofpackets"+ nosofpackets);

					BufferedInputStream bis5 = new BufferedInputStream(new FileInputStream(myFile));
					OutputStream os1 = socket.getOutputStream();
					DataOutputStream bos5 = new DataOutputStream(os1);
					bos5.writeUTF(String.valueOf(fileSize));
					
					for(double i=0; i<nosofpackets+1; i++) 
					{
						int cipher_i[];
						int prev_cipher[] = {};
						
						byte[] mybytearray = new byte[packetsize];
						bis5.read(mybytearray, 0, mybytearray.length);
					//	System.out.println("Packet:"+(i+1));
						OutputStream os5 = socket.getOutputStream();
						
						String temp5 = new String(mybytearray);
						
						if(i == 0)
						{
							String b_i = calculateRFC2104HMAC(IV,key);
							cipher_i = xor(temp5,b_i);	
							prev_cipher = cipher_i.clone();
						}
						else
						{
							String b_i = calculateRFC2104HMAC(Arrays.toString(prev_cipher),key);
							cipher_i = xor(temp5,b_i);
							prev_cipher = cipher_i.clone();
						}
						
						byte[] arrayToWrite = int2byte(cipher_i);
						
						os5.write(arrayToWrite, 0,arrayToWrite.length);
						os5.flush();
					}
					 System.out.println("File upload complete");
					 break;
				
				case 3:
					Timestamp timestamp = new Timestamp(System.currentTimeMillis());
					String time = String.valueOf(timestamp);
					
					System.out.println("Nonce send "+time);
					
					OutputStream os9= socket.getOutputStream();
					DataOutputStream dos9 = new DataOutputStream(os9);
					dos9.writeUTF(time);
					
					InputStream is9 = socket.getInputStream();
					DataInputStream in9 = new DataInputStream(is9);
					String retval = String.valueOf(in9.readUTF());
					
					Cipher cipher = Cipher.getInstance("RSA");
					PublicKey pubkey = get("public_key.der");
					
					Base64.Decoder decoder = Base64.getDecoder();
					cipher.init(Cipher.DECRYPT_MODE, pubkey);
					String decrypted = new String(cipher.doFinal(decoder.decode(retval)));
					System.out.println("Nonce received: "+decrypted);
			
					if(decrypted.equals(time))
						System.out.println("Nonce matched");
					
					System.out.println("Certificate Verification result "+verifycertificate(socket));
					break;
					
				case 4:
					generateKey(socket);
					break;		
				case 5:
					System.exit(0);
					socket.close();
					break;             
			}
		}
	}

		public static boolean verifycertificate(Socket socket1) throws Exception
		{
		    int filesize=1022386; 
		    int bytesRead;
			int currentTot = 0;
            byte[] bytearray = new byte [filesize]; 
            InputStream is = socket1.getInputStream(); 
            FileOutputStream fos = new FileOutputStream("copy11.crt"); 
            BufferedOutputStream bos = new BufferedOutputStream(fos); 
            bytesRead = is.read(bytearray,0,bytearray.length); 
            currentTot = bytesRead; 
            do 
            { 
                bytesRead = is.read(bytearray, currentTot, (bytearray.length-currentTot)); 
                if(bytesRead >= 0) 
                currentTot += bytesRead; 
            } while(bytesRead > -1);
            bos.write(bytearray, 0 , currentTot); 
            bos.flush();
            bos.close();
		    		
			
		try
		{
			
	        InputStream caInputStream = new FileInputStream("ashkan-certificate.crt");
	        InputStream serverCertInputStream = new FileInputStream("copy11.crt");
	        X509Certificate caCertificate = X509Certificate.getInstance(caInputStream);
	        X509Certificate serverCertificate = X509Certificate.getInstance(serverCertInputStream);
		
	        PublicKey caCertificatePublicKey = caCertificate.getPublicKey();

	        serverCertificate.checkValidity();

	        boolean result = true;
	        try {
	            serverCertificate.verify(caCertificatePublicKey);
				
				PublicKey key = serverCertificate.getPublicKey();
				byte[] pubBytes = key.getEncoded();
				KeyFactory kf = KeyFactory.getInstance("RSA");
				PublicKey pub_recovered = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
			//	System.out.println("Key "+ pub_recovered.toString());
			//	System.out.println("public key algorithm = " + serverCertificate.getPublicKey().getAlgorithm());
	        } catch (Exception e) {
	            e.printStackTrace();
	            result = false;
	        }
			
			return result;
		}
		catch(Exception e1)
		{
			System.out.println(e1);
		}
        return false;
	
		}
		
		public static long  power(long  a, long  b,long  P)
		{ 
			if (b == 1)
				return a;
	 
			else
				return (((long)Math.pow(a, b)) % P);
		}
		
		public static void generateKey(Socket socket) throws Exception
		{
			Random rand = new Random();
			
			P = leftLimit + (long) (Math.random() * (rightLimit - leftLimit));
			OutputStream os11=socket.getOutputStream();
		//	System.out.println("os11 created");
			
			DataOutputStream dos11=new DataOutputStream(os11);
			dos11.writeUTF(String.valueOf(P));
		//	dos11.flush();
		//	dos11.close();
		//	System.out.println("P sent");
			
			G = leftLimit + (long) (Math.random() * (rightLimit - leftLimit));
			OutputStream os1=socket.getOutputStream();
		//	System.out.println("os1 created");
			DataOutputStream dos1=new DataOutputStream(os1);
			dos1.writeUTF(String.valueOf(G));
			dos1.flush();
		//	dos1.close();
		//	System.out.println("G sent");
			
			b = leftLimit + (long) (Math.random() * (rightLimit - leftLimit));
		//	System.out.println("The private key b for Bob : "+ b);
			
			y = power(G, b, P); // gets the generated key
			OutputStream os2=socket.getOutputStream();
			DataOutputStream dos2=new DataOutputStream(os2);
			dos2.writeUTF(String.valueOf(y));
			dos2.flush();
		//	dos2.close();
		//	System.out.println("y sent"+y);
			
			InputStream is1=socket.getInputStream();
			DataInputStream dis=new DataInputStream(is1);
			x=Long.valueOf(dis.readUTF());
			
		//	System.out.println("x received"+x);
			
			kb = power(x, b, P);
			
			System.out.println("Shared Secret key for the Client is : "+ kb);
		}

		public static int[] convertToIntArray(byte[]src)
		{
			int dstLength = src.length >>> 2;
			int[]dst = new int[dstLength];
			
			for (int i=0; i<dstLength; i++) {
				int j = i << 2;
				int x = 0;
				x += (src[j++] & 0xff) << 0;
				x += (src[j++] & 0xff) << 8;
				x += (src[j++] & 0xff) << 16;
				x += (src[j++] & 0xff) << 24;
				dst[i] = x;
			}
			return dst;
		}
	
	private static String toHexString(byte[] bytes) 
	{
		Formatter formatter = new Formatter();
		
		for (byte b : bytes) {
			formatter.format("%02x", b);
		}

		return formatter.toString();
	}

	public static String calculateRFC2104HMAC(String data, String key)throws SignatureException, NoSuchAlgorithmException,InvalidKeyException
	{
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
		mac.init(signingKey);
		return toHexString(mac.doFinal(data.getBytes()));
	}
	
	public static int[] xor(String plaintext, String b)
	{
		int cipher[] = new int[plaintext.length()];
		
		for(int i =0; i<plaintext.length();i++)
        {
        	cipher[i] = Integer.valueOf(plaintext.charAt(i)) ^ Integer.valueOf(b.charAt(i % (b.length() - 1)));
        }
		return cipher;
	}
	
	public static String reversexor(int cipher[], String b)
	{
		String plain = "";
		
		for(int i =0; i<cipher.length;i++)
        {
			plain += (char) ((cipher[i]) ^ (int) b.charAt(i % (b.length() - 1)));
		}
		return plain;
	}	

	public static byte[] int2byte(int[]src)
	{
		int srcLength = src.length;
		byte[]dst = new byte[srcLength << 2];
		
		for (int i=0; i<srcLength; i++) {
			int x = src[i];
			int j = i << 2;
			dst[j++] = (byte) ((x >>> 0) & 0xff);           
			dst[j++] = (byte) ((x >>> 8) & 0xff);
			dst[j++] = (byte) ((x >>> 16) & 0xff);
			dst[j++] = (byte) ((x >>> 24) & 0xff);
		}
		return dst;
	}	
	
	public static PublicKey get(String filename)throws Exception
	{

		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
    }
}