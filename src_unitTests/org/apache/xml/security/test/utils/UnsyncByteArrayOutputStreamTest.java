/*
 * Copyright  1999-2009 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.xml.security.test.utils;

import java.lang.reflect.Field;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.xml.security.utils.UnsyncByteArrayOutputStream;

/**
 * Tests for SANTUARIO-334: UnsyncByteArrayOutputStream must not hang (or
 * corrupt its state through int overflow) when the buffered data approaches
 * Integer.MAX_VALUE bytes.
 */
public class UnsyncByteArrayOutputStreamTest extends TestCase {

	public UnsyncByteArrayOutputStreamTest(String name) {
		super(name);
	}

	public static Test suite() {
		return new TestSuite(UnsyncByteArrayOutputStreamTest.class);
	}

	/**
	 * A single write much larger than the current buffer must grow the buffer
	 * far enough to hold all of it.
	 */
	public void testWriteByteArrayLargerThanBuffer() {
		UnsyncByteArrayOutputStream out = new UnsyncByteArrayOutputStream();
		byte[] data = pattern(200 * 1024);
		out.write(data);
		assertBytes(data, out.toByteArray());
	}

	public void testWriteByteArrayRangeLargerThanBuffer() {
		UnsyncByteArrayOutputStream out = new UnsyncByteArrayOutputStream();
		out.write(1);
		byte[] data = pattern(200 * 1024);
		out.write(data, 7, data.length - 7);
		byte[] result = out.toByteArray();
		assertEquals(1 + data.length - 7, result.length);
		assertEquals(1, result[0]);
		for (int i = 7; i < data.length; i++) {
			assertEquals(data[i], result[i - 6]);
		}
	}

	public void testWriteSingleBytesGrowsBuffer() {
		UnsyncByteArrayOutputStream out = new UnsyncByteArrayOutputStream();
		byte[] data = pattern(100 * 1024);
		for (int i = 0; i < data.length; i++) {
			out.write(data[i]);
		}
		assertBytes(data, out.toByteArray());
	}

	/**
	 * Writing a byte when the stream already holds Integer.MAX_VALUE bytes
	 * must fail with an OutOfMemoryError instead of overflowing the position.
	 */
	public void testWriteIntAtIntegerLimit() throws Exception {
		UnsyncByteArrayOutputStream out = new UnsyncByteArrayOutputStream();
		setField(out, "pos", Integer.MAX_VALUE);
		try {
			out.write(1);
			fail("OutOfMemoryError expected");
		} catch (OutOfMemoryError expected) {
			// expected
		}
	}

	/**
	 * pos + len overflowing an int must be rejected before any copy happens.
	 */
	public void testWriteByteArrayOverflowingIntegerLimit() throws Exception {
		UnsyncByteArrayOutputStream out = new UnsyncByteArrayOutputStream();
		setField(out, "pos", Integer.MAX_VALUE - 5);
		try {
			out.write(new byte[10]);
			fail("OutOfMemoryError expected");
		} catch (OutOfMemoryError expected) {
			// expected
		}
	}

	public void testWriteByteArrayRangeOverflowingIntegerLimit()
		throws Exception {
		UnsyncByteArrayOutputStream out = new UnsyncByteArrayOutputStream();
		setField(out, "pos", Integer.MAX_VALUE - 5);
		try {
			out.write(new byte[20], 5, 10);
			fail("OutOfMemoryError expected");
		} catch (OutOfMemoryError expected) {
			// expected
		}
	}


	private static void setField(UnsyncByteArrayOutputStream out, String name,
								 int value) throws Exception {
		Field field =
			UnsyncByteArrayOutputStream.class.getDeclaredField(name);
		field.setAccessible(true);
		field.setInt(out, value);
	}

	private static byte[] pattern(int length) {
		byte[] data = new byte[length];
		for (int i = 0; i < length; i++) {
			data[i] = (byte) (i * 31 + 7);
		}
		return data;
	}

	private static void assertBytes(byte[] expected, byte[] actual) {
		assertEquals(expected.length, actual.length);
		for (int i = 0; i < expected.length; i++) {
			if (expected[i] != actual[i]) {
				fail("byte " + i + " differs: expected " + expected[i]
					 + " but was " + actual[i]);
			}
		}
	}
}
