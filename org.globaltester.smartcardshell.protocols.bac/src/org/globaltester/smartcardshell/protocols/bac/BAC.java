package org.globaltester.smartcardshell.protocols.bac;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.globaltester.logging.logger.TestLogger;
import org.globaltester.smartcardshell.protocols.icao9303.MRZ;
import org.globaltester.smartcardshell.protocols.securemessaging.Crypto;

import de.cardcontact.tlv.HexString;

public class BAC {
	
	private MRZ mrz;
	
	private final int SECRETLENGTH = 32;
	
	private final int MACLENGTH = 8;

	private SecretKey kEnc;
	private SecretKey kMac;
	
	private SecretKey skEnc;
	private SecretKey skMac;	
	
	public BAC(){
	}
	
	public void setMRZ(MRZ mrz){
		this.mrz = mrz;
	}
	
	public String getMRZ(){
		return mrz.toString();
	}
	
	public SecretKey getKenc(){
		return kEnc;
	}

	public SecretKey getKmac(){
		return kMac;
	}

	public SecretKey getSKenc(){
		return skEnc;
	}

	public SecretKey getSKmac(){
		return skMac;
	}
	
	public byte[] computeMutualAuthenticateData(byte[] rndIFD, byte[] rndICC, byte[] kIFD) {
		
		/*
		 * Create the input s for the cryptogram and the MAC
		 */
		byte[] s = new byte[SECRETLENGTH];
		System.arraycopy(rndIFD, 0, s, 0, 8);
		System.arraycopy(rndICC, 0, s, 8, 8);
		System.arraycopy(kIFD, 0, s, 2 * 8, 16);

		byte[] e = Crypto.computeCryptogram(s, kEnc, 1);
		System.out.println("E_IFD: "+HexString.hexifyByteArray(e));
		
		byte[] m = Crypto.computeMAC(e, kMac); 
		System.out.println("M_IFD: "+HexString.hexifyByteArray(m));

		int len = e.length + m.length;
		byte[] data = new byte[len];
		System.arraycopy(e, 0, data, 0, e.length);
		System.arraycopy(m, 0, data, e.length, m.length);
		
		return data;
	}
	
	public byte[] getKicc(byte[] response) {
		/*
		 * decrypt message and return kicc
		 */
		byte[] y = new byte[SECRETLENGTH];
		System.arraycopy(response, 0, y, 0, SECRETLENGTH);
		y = Crypto.computeCryptogram(y, kEnc, Cipher.DECRYPT_MODE);
		byte[] kicc = new byte[16];
		System.arraycopy(y, 16, kicc, 0, 16);
		return kicc;
	}

	
	
	public void deriveMrzKeys(){
		
		kEnc = Crypto.deriveKey(mrz.computeKeySeed(), (byte) 01);
		System.out.println("Key Enc: "+HexString.hexifyByteArray(kEnc.getEncoded()));
		
		kMac = Crypto.deriveKey(mrz.computeKeySeed(), (byte) 02);
		System.out.println("Key Mac: "+HexString.hexifyByteArray(kMac.getEncoded()));
		
	}
	
	public void deriveSessionKeys(byte[] keySeed){
		
		skEnc = Crypto.deriveKey(keySeed, (byte) 1);
		System.out.println("SK Enc: "+HexString.hexifyByteArray(skEnc.getEncoded()));

		skMac = Crypto.deriveKey(keySeed, (byte) 2);
		System.out.println("SK Mac: "+HexString.hexifyByteArray(skMac.getEncoded()));

	}
	
	
	
	public boolean verifyMutualAuthenticateResponse(byte[] response, SecretKey kmac) {

		byte[] cryptogram = new byte[SECRETLENGTH];
		System.arraycopy(response, 0, cryptogram, 0, SECRETLENGTH);
		byte[] macMA = new byte[MACLENGTH];
		System.arraycopy(response, SECRETLENGTH, macMA, 0, MACLENGTH);

		byte[] checksum = Crypto.computeMAC(cryptogram, kmac);
		if (!HexString.hexifyByteArray(macMA).equalsIgnoreCase(
				HexString.hexifyByteArray(checksum))) {
			System.out.println("MAC expected: "
					+ HexString.hexifyByteArray(checksum));
			System.out.println("MAC received: " + HexString.hexifyByteArray(macMA));
			System.out.println("Error while generating checksum");
			return false;
		}
		System.out.println("MAC of Mutual Authenticate Response: " +HexString.hexifyByteArray(macMA));
		return true;
	}
	
	public byte[] computeKeySeed(byte[] kIFD, byte[] kICC){
		// Calculate XOR of kIFD and kICC:
		byte[] keySeed = new byte[16];
		for (int i = 0; i < 16; i++) {
			keySeed[i] = (byte) ((kIFD[i] & 0xFF) ^ (kICC[i] & 0xFF));
		}
		System.out.println("Key Seed: "+HexString.hexifyByteArray(keySeed));
		return keySeed;
	}

	public static byte[] getRandomBytes(int numberOfBytes){
		byte[] rndBytes = new byte[numberOfBytes];
		
		try {
			SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
			rng.nextBytes(rndBytes);
		} catch (NoSuchAlgorithmException e1) {
			TestLogger.error(e1);
		}
		return rndBytes;
	}
	
	public static byte[] calculateInitialSendSequenceCounter(byte[] rndICC, byte[] rndIFD){
		
		byte[] ssc = new byte[8];
		System.arraycopy(rndICC, 4, ssc, 0, 4);
		System.arraycopy(rndIFD, 4, ssc, 4, 4);
		
		return ssc;
	}
}
