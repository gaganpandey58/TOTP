package com.gagan.totp.config;

import com.gagan.totp.statics.Encoder;
import com.gagan.totp.statics.HashFunction;

import java.util.concurrent.TimeUnit;

public class AuthenticatorConfig
{
    private long timeStepSizeInMillis = TimeUnit.SECONDS.toMillis(30);
    private int codeDigits = 6;
    private int keyModulus = (int) Math.pow(10, codeDigits);
    private Encoder encoder = Encoder.BASE32;
    private HashFunction hashFunction = HashFunction.HmacSHA1;

    public int getKeyModulus() { return keyModulus; }

    public Encoder getEncoder() { return encoder; }

    public long getTimeStepSizeInMillis() { return timeStepSizeInMillis; }

    public HashFunction getHashFunction() { return hashFunction; }
}
