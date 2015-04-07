package com.notsocomplex.hmac;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class HMACGeneratorTest {
	
	private HMACGenerator generator;

	@Before
	public void before() {
		generator = new HMACGenerator();
	}

	@Test
	public void testMD5() throws Exception {
		Assert.assertEquals(
			"52514ea2d6f642a0f23524c8ddd8d06e", 
			generator.createHMAC("HMACMD5", "John Watson", "Sherlock Holmes")
		);

	}

	@Test
	public void testSHA256() throws Exception {
		Assert.assertEquals(
			"d6870270ae485f5c250b1820533ad9b7a869f383998da8f4e1607f8c38f2aa23",
			generator.createHMAC("HMACSHA256", "John Watson", "Sherlock Holmes")
		);
	}
	
}
