package com.notsocomplex.hmac;

import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HMACGenerator {

	/**
	 * Generates a hash-based message authentication code
	 * 
	 * @param algorithm
	 *            The name of the algorithm to use
	 * @param secretKey
	 *            The secret key
	 * @param message
	 *            The message to generate the hmac for
	 * @return A hash-based message authentication code
	 * @throws NoSuchAlgorithmException
	 *             If the algorithm is not supported by the provider
	 * @throws InvalidKeyException
	 *             If the key is invalid
	 */
	public String createHMAC(String algorithm, String secretKey, String message)
			throws NoSuchAlgorithmException, InvalidKeyException {

		// Create a key instance using the bytes of our secret key argument and
		// the proper algorithm
		SecretKey key = new SecretKeySpec(secretKey.getBytes(), algorithm);

		// Create a Mac instance using Bouncy Castle as the provider
		// and the specified algorithm
		Mac mac = Mac.getInstance(algorithm, new BouncyCastleProvider());

		// Initialize using the key and update with the data to
		// generate the mac from
		mac.init(key);
		mac.update(message.getBytes());

		// Perform the mac operation
		byte[] encrypted = mac.doFinal();

		StringWriter writer = new StringWriter();

		// Convert to hexadecimal representation
		for (byte b : encrypted) {
			writer.append(String.format("%02x", b));
		}

		return writer.toString();

	}

}