package com.gagan.totp;

import com.gagan.totp.config.AuthenticatorConfig;
import com.gagan.totp.exception.AuthenticatorException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

public final class Authenticator {
    private final AuthenticatorConfig config;

    public Authenticator() {
        config = new AuthenticatorConfig();
    }

    String calculateCode(byte[] key, long tm) {
        byte[] data = new byte[8];
        long value = tm;

        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, config.getHashFunction().toString());

        try {
            Mac mac = Mac.getInstance(config.getHashFunction().toString());

            mac.init(signKey);

            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0xF;
            long truncatedHash = 0;

            for (int i = 0; i < 4; ++i) {
                truncatedHash <<= 8;
                truncatedHash |= (hash[offset + i] & 0xFF);
            }

            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= config.getKeyModulus();

            return String.format("%06d", (int) truncatedHash);
        }
        catch (Exception exception) {
            throw new AuthenticatorException("An error occurred while generating OTP code", exception.getCause());
        }
    }

    private long getTimeWindowFromTime(long time) {
        return time / this.config.getTimeStepSizeInMillis();
    }

    private byte[] decodeSecret(String secret) {
        switch (config.getEncoder()) {
            case BASE32:
                Base32 codec32 = new Base32();
                return codec32.decode(secret.toUpperCase());
            case BASE64:
                Base64 codec64 = new Base64();
                return codec64.decode(secret);
            default:
                throw new AuthenticatorException("Unknown Encode type.");
        }
    }

    public String getTotpPassword(String secret) {
        return getTotpPassword(secret, new Date().getTime());
    }

    public String getTotpPassword(String secret, long time) {
        return calculateCode(decodeSecret(secret), getTimeWindowFromTime(time));
    }
}
