package net.steelphoenix.poa;

import java.util.Random;

import javax.crypto.BadPaddingException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;

public class PaddingTest {

	private static final Random RANDOM = new Random();

	private int blocksize;
	private byte[] data;

	@BeforeEach
	public void setup() {
		this.blocksize = RANDOM.nextInt(255) + 1;
		this.data = new byte[RANDOM.nextInt(1025)];
		RANDOM.nextBytes(data);
	}

	@RepeatedTest(value = 100)
	public void testPadUnpadEqual() {
		byte[] result;
		try {
			result = PKCS7Padding.unpad(blocksize, PKCS7Padding.pad(blocksize, data));
		} catch (BadPaddingException exception) {
			Assertions.fail("Bad padding on valid padding", exception);
			return;
		}

		Assertions.assertArrayEquals(data, result);
	}

	@RepeatedTest(value = 100)
	public void testPadSize() {
		byte[] padded = PKCS7Padding.pad(blocksize, data);

		Assertions.assertTrue(data.length < padded.length, "Padded data size is not larger than data size");
		float blocks = ((float) padded.length) / blocksize;
		Assertions.assertTrue(((int) blocks) == blocks, "Padded data is not block aligned");
		Assertions.assertEquals(Math.floor((((float) data.length) / blocksize) + 1F), blocks);
	}

	@RepeatedTest(value = 100)
	public void testInvalidPadSize() {
		byte[] padded = PKCS7Padding.pad(blocksize, data);

		byte[] invalid = new byte[padded.length - (blocksize == 1 ? 0 : RANDOM.nextInt(blocksize - 1)) - 1];
		System.arraycopy(padded, 0, invalid, 0, invalid.length);

		Assertions.assertThrows(BadPaddingException.class, () -> PKCS7Padding.unpad(blocksize, invalid));
	}

	@RepeatedTest(value = 100)
	public void testInvalidPad() {
		byte[] padded = PKCS7Padding.pad(blocksize, data);

		int pads = padded[padded.length - 1] & 0xFF;
		
		if (pads == 1) {
			int i;
			while ((i = RANDOM.nextInt(blocksize) + 1) == pads) {
				// Nothing
			}
			padded[padded.length - 1] = (byte) i;
		}
		else {
			for (int i = pads == 2 ? 0 : RANDOM.nextInt(pads - 2); i >= 0; i--) {
				// max - min + 1 .. + min
				int j = RANDOM.nextInt(pads - 1) + padded.length - pads;
				
				int k;
				while ((k = RANDOM.nextInt(blocksize) + 1) == pads) {
					// Nothing
				}
				padded[j] = (byte) k;
			}
			
		}

		Assertions.assertThrows(BadPaddingException.class, () -> PKCS7Padding.unpad(blocksize, padded));
	}
	
	@RepeatedTest(value = 100)
	public void testPad() {
		byte[] padded = PKCS7Padding.pad(blocksize, data);

		byte[] bytes = new byte[data.length];
		System.arraycopy(padded, 0, bytes, 0, data.length);

		Assertions.assertArrayEquals(data, bytes);
		
		for (int i = data.length; i < padded.length; i++) {
			Assertions.assertEquals((byte) (padded.length - data.length), padded[i]);
		}
	}
}
