package net.steelphoenix.poa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;

import net.steelphoenix.poa.PaddingOracle.Validator;

public class PaddingOracleTest {
	
	/**
	 * Block size in bytes.
	 */
	private static final byte BLOCK_SIZE = 16;

	/**
	 * Strong secure random to use.
	 */
	private static final SecureRandom RANDOM;
	
	/**
	 * AES Key generator.
	 */
	private static final KeyGenerator KEYGEN;
	
	/**
	 * Simple validator.
	 */
	private static final Validator VALIDATOR = new SimpleValidator(BLOCK_SIZE);

	private byte[] plain;
	private PaddingOracle oracle;
	
	static {
		try {
			RANDOM = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException exception) {
			// Each Java platform implementation is required to support at least one strong SecureRandom
			throw new AssertionError("No strong SecureRandom found", exception);
		}
		
		KeyGenerator generator;
		try {
			generator = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException exception) {
			// Each Java platform implementation is required to support AES (128)
			throw new AssertionError("No AES generator found", exception);
		}
		generator.init(128, RANDOM);
		KEYGEN = generator;
	}
	
	@BeforeEach
	public void setup() {
		// Random amount of bytes
		int bytes = RANDOM.nextInt(401) + 100;

		Key key = KEYGEN.generateKey();
		byte[] iv = new byte[BLOCK_SIZE];
		RANDOM.nextBytes(iv);
		byte[] plain = new byte[bytes];
		RANDOM.nextBytes(plain);
		this.plain = PKCS7Padding.pad(BLOCK_SIZE, plain);

		Cipher cipher = getAESCBCNoPaddingCipher();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		} catch (InvalidAlgorithmParameterException | InvalidKeyException exception) {
			throw new AssertionError("Could not initialize cipher", exception);
		}		

		byte[] encrypted;
		try {
			encrypted = cipher.doFinal(this.plain);
		} catch (IllegalBlockSizeException | BadPaddingException exception) {
			throw new AssertionError("Could not encrypt data", exception);
		}

		byte[] data = new byte[iv.length + encrypted.length];
		System.arraycopy(iv, 0, data, 0, iv.length);
		System.arraycopy(encrypted, 0, data, iv.length, encrypted.length);

		this.oracle = new PaddingOracle(BLOCK_SIZE, key, data, VALIDATOR);
	}
	
	@AfterEach
	public void close() {
		this.plain = null;
		this.oracle = null;
	}
	
	@RepeatedTest(value = 100)
	public void test() {
		Assertions.assertArrayEquals(plain, oracle.run());
	}
	
	private static Cipher getAESCBCNoPaddingCipher() {
		try {
			return Cipher.getInstance("AES/CBC/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException exception) {
			// Each Java platform implementation is required to support this algorithm
			throw new AssertionError("No AES/CBC/NoPadding cipher found", exception);
		}
	}

	private static class SimpleValidator implements Validator {
		
		private final byte blocksize;
		
		private SimpleValidator(byte blocksize) {
			if (blocksize <= 0) {
				throw new IllegalArgumentException("Block size cannot be nonpositive");
			}
			this.blocksize = blocksize;
		}

		@Override
		public boolean test(Key key, byte[] data) throws Exception {
			byte[] iv = new byte[blocksize];
			System.arraycopy(data, 0, iv, 0, blocksize);
			Cipher cipher = getAESCBCNoPaddingCipher();
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			byte[] encrypted = new byte[data.length - blocksize];
			System.arraycopy(data, blocksize, encrypted, 0, encrypted.length);
			
			try {
				PKCS7Padding.unpad(blocksize, cipher.doFinal(encrypted));
				return true;
			} catch (BadPaddingException exception) {
				return false;
			}
		}
	} 
}
