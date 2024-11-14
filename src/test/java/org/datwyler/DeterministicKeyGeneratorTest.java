package org.datwyler;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class DeterministicKeyGeneratorTest {

    private static DeterministicKeyGenerator keyGen;

    @BeforeAll
    public static void init() {
        keyGen = new DeterministicKeyGenerator();
    }

    @Test
    public void testDeterministic() throws NoSuchAlgorithmException {
        Instant ts = Instant.now();
        UUID uuid = UUID.randomUUID();

        var key1 = keyGen.generateSharedKey(ts, uuid);
        var key2 = keyGen.generateSharedKey(ts, uuid);

        assertArrayEquals(key1, key2);
    }

    @Test
    public void givenDifferentTimestamp_whenGenerateKey_thenUniqueResult() throws NoSuchAlgorithmException {
        var ts1 = Instant.now();
        UUID uuid = UUID.randomUUID();
        var ts2 = ts1.plusSeconds(20);

        assertNotEquals(ts1, ts2);

        var key1 = keyGen.generateSharedKey(ts1, uuid);
        var key2 = keyGen.generateSharedKey(ts2, uuid);

        assertFalse(Arrays.equals(key1, key2));
    }

    @Test
    public void givenDifferentUUID_whenGenerateKey_thenUniqueResult() throws NoSuchAlgorithmException {
        var ts = Instant.now();

        var key1 = keyGen.generateSharedKey(ts, UUID.randomUUID());
        var key2 = keyGen.generateSharedKey(ts, UUID.randomUUID());

        assertFalse(Arrays.equals(key1, key2));
    }
}
