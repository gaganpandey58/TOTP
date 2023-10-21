package com.gagan.totp;

import org.junit.Test;
public class AuthTest
{
    private static final String SECRET_KEY = "IZLTETCOJZLFSRSNKNHQ";
    @Test
    public void createAndAuthenticate()
    {
        final Authenticator authenticator = new Authenticator();
        String otpCode = authenticator.getTotpPassword(SECRET_KEY);
        System.out.println(otpCode);
    }

}
