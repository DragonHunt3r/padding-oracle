package net.steelphoenix.poa;

import java.util.Arrays;

import javax.crypto.BadPaddingException;

/**
 * PKCS7 Padding.
 *
 * @author SteelPhoenix
 */
public class PKCS7Padding {

	private PKCS7Padding() {
		// Nothing
	}

	/**
	 * Pad data.
	 *
	 * @param size Block size.
	 * @param data Target data.
	 * @return the padded data.
	 */
	public static byte[] pad(int size, byte[] data) {
		// Preconditions
		if (data == null) {
			throw new NullPointerException("Data cannot be null");
		}
		if (size <= 0x00 || size > 0xFF) {
			throw new IllegalArgumentException("Invalid block size: " + size);
		}

		int pads = size - (data.length % size);

		byte[] result = new byte[data.length + pads];
		System.arraycopy(data, 0, result, 0, data.length);
		Arrays.fill(result, data.length, result.length, (byte) pads);
		return result;
	}

	/**
	 * Unpad padded data.
	 *
	 * @param size Block size.
	 * @param data Target data.
	 * @return the unpadded data.
	 * @throws BadPaddingException If the data is not padded correctly.
	 */
	public static byte[] unpad(int size, byte[] data) throws BadPaddingException {
		// Preconditions
		if (data == null) {
			throw new NullPointerException("Data cannot be null");
		}
		if (size <= 0x00 || size > 0xFF) {
			throw new IllegalArgumentException("Invalid block size: " + size);
		}
		float blocks = ((float) data.length) / size;
		if (((int) blocks) != blocks) {
			throw new BadPaddingException("Invalid data size: " + data.length);
		}

		int pads = data[data.length - 1] & 0xFF;
		if (pads == 0) {
			throw new BadPaddingException("No padding bytes");
		}

		for (int i = data.length - 1; i > data.length - 1 - pads; i--) {
			if ((data[i] & 0xFF) != pads) {
				throw new BadPaddingException(String.format("Expected 0x%02X, but found 0x%02X", pads, data[i]));
			}
		}

		byte[] result = new byte[data.length - pads];
		System.arraycopy(data, 0, result, 0, result.length);
		return result;
	}
}
