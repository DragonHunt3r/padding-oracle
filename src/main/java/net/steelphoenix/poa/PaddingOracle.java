package net.steelphoenix.poa;

import java.security.Key;

/**
 * A padding oracle
 *
 * @author SteelPhoenix
 */
public class PaddingOracle {

	private final byte size;
	private final Key key;
	private final byte[] data;
	private final Validator validator;

	public PaddingOracle(byte size, Key key, byte[] data, Validator validator) {
		if (key == null) {
			throw new NullPointerException("Key cannot be null");
		}
		if (data == null) {
			throw new NullPointerException("Data cannot be null");
		}
		if (validator == null) {
			throw new NullPointerException("Validator cannot be null");
		}
		if (size <= 0) {
			throw new IllegalArgumentException("Invalid size: " + size);
		}
		float blocks = ((float) data.length) / size;
		if (((int) blocks) != blocks || blocks == 1F) {
			throw new IllegalArgumentException("Invalid data size: " + data.length);
		}
		this.size = size;
		this.key = key;
		this.data = data.clone();
		this.validator = validator;
	}

	/**
	 * Run the padding oracle.
	 *
	 * @return the plaintext (including padding bytes).
	 */
	public byte[] run() {
		byte[] plaintext = new byte[data.length - size];

		// For each cipher block
		// Skip the IV
		for (int i = size; i < data.length; i += size) {

			// Copy so it can be modified freely
			byte[] clone = new byte[i + size];
			System.arraycopy(data, 0, clone, 0, clone.length);

			// For each byte in the block
			for (byte j = (byte) (size - 1); j >= 0; j--) {
				int offset = i - size;

				// Fill previous values
				for (int k = size - 1; k > j; k--) {
					clone[offset + k] = (byte) (data[offset + k] ^ plaintext[offset + k] ^ (size - j));
				}

				// Try every value
				for (int k = 0x00; k <= 0x100; k++) {

					if (k == 0x100) {
						if (j == size - 1) {
							throw new RuntimeException("Could not find value");
						}
						
						// Reset
						j = (byte) (size - 1);
						k = plaintext[offset + j];
						continue;
					}

					clone[offset + j] = (byte) (data[offset + j] ^ k ^ (16 - j));

					boolean success;
					try {
						success = validator.test(key, clone);
					} catch (Exception exception) {
						throw new RuntimeException("Validator threw an exception", exception);
					}

					// Valid padding
					if (success) {
						plaintext[offset + j] = (byte) k;
						break;
					}
				}
			}
		}
		return plaintext;
	}

	/**
	 * A guess validator.
	 *
	 * @author SteelPhoenix
	 */
	@FunctionalInterface
	public static interface Validator {

		/**
		 * A padding predicate.
		 *
		 * @param key Target key.
		 * @param data Initialization vector and ciphertext.
		 * @return if the unencrypted data is padded correctly.
		 * @throws Exception If something goes wrong testing.
		 */
		public boolean test(Key key, byte[] data) throws Exception;
	}
}
