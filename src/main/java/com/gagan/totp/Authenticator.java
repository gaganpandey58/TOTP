package com.gagan.totp;

import com.gagan.totp.config.AuthenticatorConfig;
import com.gagan.totp.exception.AuthenticatorException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public final class Authenticator {
    private final AuthenticatorConfig config;

    public Authenticator() {
        config = new AuthenticatorConfig();
    }

    String calculateCode(byte[] key, long tm) {
        byte[] data = prepareData(tm);
        SecretKeySpec signKey = getSignKey(key);
        byte[] hash = computeHash(data, signKey);

        long truncatedHash = calculateTruncatedHash(hash);
        truncatedHash %= config.getKeyModulus();

        return formatTruncatedHash(truncatedHash);
    }

    byte[] computeHash(byte[] data, SecretKeySpec signKey) {
        try {
            return calculateHash(data, signKey);
        } catch (Exception exception) {
            throw new AuthenticatorException("An error occurred while computing hash", exception.getCause());
        }
    }

    String formatTruncatedHash(long truncatedHash) {
        return String.format("%06d", (int) truncatedHash);
    }

    byte[] prepareData(long tm) {
        byte[] data = new byte[8];
        for (int i = 8; i-- > 0; tm >>>= 8) {
            data[i] = (byte) tm;
        }
        return data;
    }

    SecretKeySpec getSignKey(byte[] key) {
        String hashFunction = config.getHashFunction().toString();
        return new SecretKeySpec(key, hashFunction);
    }

    byte[] calculateHash(byte[] data, SecretKeySpec signKey) throws NoSuchAlgorithmException, InvalidKeyException {
        String hashFunction = config.getHashFunction().toString();
        Mac mac = Mac.getInstance(hashFunction);
        mac.init(signKey);
        return mac.doFinal(data);
    }

    long calculateTruncatedHash(byte[] hash) {
        int offset = hash[hash.length - 1] & 0xF;
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
        truncatedHash &= 0x7FFFFFFF;
        return truncatedHash;
    }

    private long getTimeWindowFromTime(long time) {
        return time / this.config.getTimeStepSizeInMillis();
    }

    private byte[] decodeSecret(String secret) {
        switch (config.getEncoder()) {
            case BASE32:
                return decodeBase32Secret(secret);
            case BASE64:
                return decodeBase64Secret(secret);
            default:
                throw new AuthenticatorException("Unknown Encode type.");
        }
    }

    private byte[] decodeBase32Secret(String secret) {
        Base32 base32Codec = new Base32();
        return base32Codec.decode(secret.toUpperCase());
    }

    private byte[] decodeBase64Secret(String secret) {
        Base64 base64Codec = new Base64();
        return base64Codec.decode(secret);
    }

    public String getTotpPassword(String secret) {
        return getTotpPassword(secret, new Date().getTime());
    }

    public String getTotpPassword(String secret, long time) {
        return calculateCode(decodeSecret(secret), getTimeWindowFromTime(time));
    }
}
