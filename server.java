import java.net.*; 
import java.io.*; 
import javax.crypto.*;
import java.math.*;
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

public class server extends Thread
{
  	Socket socket;
	ServerSocket serverSocket;
	Random rand = new Random();
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static String key = "12345678910";
	private static final String IV = "ThisIsFirstPacket";
	static long leftLimit = 1000000000000000L;
	static long rightLimit = 9999999999999999L;
	static long  P, G, x, a, y, b, ka, kb, fileSize;								// P,G,y to come from client 
	static int packetsize=1024;
	static double nosofpackets;
					
	public server(int port) throws Exception
	{	
		serverSocket = new ServerSocket(port);
	}
	
	public void run()
	{
		int bytesRead; 
		int currentTot = 0;
		
		while(true)
		{
				
			try
			{	
			 socket = serverSocket.accept();	
		//	 System.out.println("Accepted connection : " + socket);
			 
			InputStream is = socket.getInputStream();
			 DataInputStream in = new DataInputStream(is);
			 int choice = Integer.valueOf(in.readUTF());
			 
			 // 1 send 2 receive 3. certificate 4. keys 5. exit
				switch(choice)
				{
					case 1:
					key = String.valueOf(ka);
					String prev = "";
					File myFile = new File("test.txt");
					fileSize = myFile.length();
			//		System.out.println("filesize"+ fileSize);
					nosofpackets=Math.ceil(((int) myFile.length())/packetsize);
					//System.out.println("nosofpackets"+ nosofpackets);

					BufferedInputStream bis = new BufferedInputStream(new FileInputStream(myFile));
					OutputStream os1 = socket.getOutputStream();
					DataOutputStream bos = new DataOutputStream(os1);
					bos.writeUTF(String.valueOf(fileSize));
					
					for(double i=0; i<nosofpackets+1; i++) 
					{
						int cipher_i[];
						int prev_cipher[] = {};
						
						byte[] mybytearray = new byte[packetsize];
						bis.read(mybytearray, 0, mybytearray.length);
				//		System.out.println("Packet:"+(i+1));
						OutputStream os = socket.getOutputStream();
						
						String temp = new String(mybytearray);
						
						if(i == 0)
						{
							String b_i = calculateRFC2104HMAC(IV,key);
							cipher_i = xor(temp,b_i);	
							prev_cipher = cipher_i.clone();
						}
						else
						{
							String b_i = calculateRFC2104HMAC(Arrays.toString(prev_cipher),key);
							cipher_i = xor(temp,b_i);
							prev_cipher = cipher_i.clone();
						}
						
						byte[] arrayToWrite = int2byte(cipher_i);
						
						os.write(arrayToWrite, 0,arrayToWrite.length);
						os.flush();
					}
					 System.out.println("File transfer complete");
					 break;
				 
					case 2:
					key = String.valueOf(ka);
					String plainregained = "";
					int count;
					byte[] buffer = new byte[8192];
					FileOutputStream fos = new FileOutputStream("copy.txt");
					BufferedOutputStream bos1 = new BufferedOutputStream(fos);
					InputStream is1 = socket.getInputStream();
					DataInputStream bis1 = new DataInputStream(is1);
					String temp = bis1.readUTF();
					fileSize = Long.valueOf(temp);
					nosofpackets=Math.ceil(((int) fileSize)/packetsize);
					
					for(double i=0;i<nosofpackets+1;i++)
					{
						InputStream is2 = socket.getInputStream();
						byte[] mybytearray = new byte[packetsize];
						bytesRead = is2.read(mybytearray, 0,mybytearray.length );
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
							String b_i = calculateRFC2104HMAC(Arrays.toString(toCalculate),key);
							plainregained = reversexor(toCalculate,b_i);
						}
						
						byte[] bytearray = plainregained.getBytes();
					
						bos1.write(bytearray, 0,bytearray.length);
					}
					Thread.sleep(4000);	
					socket.close();
					bos1.close();
					System.out.println("File successfully uploaded");
					break;
					 
					 case 3:
					 
						Cipher cipher = Cipher.getInstance("RSA");
						PrivateKey pvtKey = getpvt("private_key.der");
						
						InputStream is9 = socket.getInputStream();
						DataInputStream in9 = new DataInputStream(is9);
						String receivedNonce = String.valueOf(in9.readUTF());
						
						cipher.init(Cipher.ENCRYPT_MODE, pvtKey);
						byte[] encrypted = cipher.doFinal(receivedNonce.getBytes());
						Base64.Encoder encoder = Base64.getEncoder();
						String encryptedString = encoder.encodeToString(encrypted);
					//	System.out.println("Encrypted: "+encryptedString);
						
						OutputStream os9= socket.getOutputStream();
						DataOutputStream dos9 = new DataOutputStream(os9);
						dos9.writeUTF(encryptedString);
						
						File transferFile1 = new File ("server-certificate.crt");
						 byte [] bytearray1 = new byte [(int)transferFile1.length()]; 
						 FileInputStream fin1 = new FileInputStream(transferFile1);
						 BufferedInputStream bin1 = new BufferedInputStream(fin1);
						 bin1.read(bytearray1,0,bytearray1.length); 
						 OutputStream os2 = socket.getOutputStream(); 
						 System.out.println("Sending Certificate...");
						 os2.write(bytearray1,0,bytearray1.length);
						 os2.flush();
						 socket.close();
						 System.out.println("Certificate transfer complete");
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
			catch(Exception e1)
			{
				e1.printStackTrace();
			}
		}	
	}
    
	public static long  power(long  a, long  b,long  P)
	{ 
		if (b == 1)
			return a;
	 
		else
			return (((long)Math.pow(a, b)) % P);
	}
	
	public static void main (String [] args )
	{
		try
		{
			 Thread t = new server(6000);
			 t.start();
		}
		
		catch(Exception e)
		{
			System.out.println(e);
		}
	 	 
	}
	
	public static void generateKey(Socket socket) throws Exception
	{
		a = leftLimit + (long) (Math.random() * (rightLimit - leftLimit));		//Server private key
		
		
		
		OutputStream osX = socket.getOutputStream();			//to send x
		DataOutputStream outX = new DataOutputStream(osX);
	//	 System.out.println("outx created");
		 
		 InputStream is = socket.getInputStream();
		 DataInputStream in = new DataInputStream(is);
		 
		 InputStream isP = socket.getInputStream();
		 DataInputStream inP = new DataInputStream(isP);
		 
		 InputStream isG = socket.getInputStream();
		 DataInputStream inG = new DataInputStream(isG);
		 
		 InputStream isY = socket.getInputStream();
		 DataInputStream inY = new DataInputStream(isY);
		 
		 P = Long.valueOf(inP.readUTF());
	//	 inP.flush();
		 G = Long.valueOf(inG.readUTF());
	//	 inG.flush();
		 y = Long.valueOf(inY.readUTF());
	//	 inY.flush();
		 
	//	 System.out.println("P: "+P);
	//	 System.out.println("G: "+G);
	//	 System.out.println("Y: "+y);
	//	 System.out.println("The private key a for Server : "+ a);
		 
		 x = power(G, a, P); 													// gets the public key generated
		 
	//	 System.out.println("The public key x for Server : "+ x);
		 outX.writeUTF(String.valueOf(x));
		 outX.flush();
		 ka = power(y, a, P); 													// Shared Secret key for server
		 
		 System.out.println("Shared secret key for server: "+ka);
		 
		 socket.close();
	}
	
	//--------------------------------------------------------------------------------
	
	public static byte[] int2byte(int[]src) {
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
	
	public static int[] convertToIntArray(byte[]src) {
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
	
	public static PrivateKey getpvt(String filename) throws Exception
	{

		    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		    PKCS8EncodedKeySpec spec =
		      new PKCS8EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePrivate(spec);
	}

}
