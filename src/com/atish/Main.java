package com.atish;

import java.io.BufferedReader;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.openssl.PEMReader;

import Decoder.BASE64Decoder;

public class Main {

    /**
     * @param args
     */
    public static void main(String[] args)
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try {
            BASE64Decoder decoder   = new BASE64Decoder();

            String b64PrivateKey    = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ0KTUlJQ1hBSUJBQUtCZ1FDYWFKSU14TEcrRmg1K2JORzBpc2l6VzAxeWRscWFVbm1pOVNnemhpL2N5V01hNGZQTw0KbEg1dXhUczB4b1loY3FyVzZCREpERlg1bzIxUGtXMFBqamFvZWxnclFQWGgzQ0hCY3l3cnZNNlBSbUd2THZvMw0Kc1J3UHpOVVFwKzRTQllCWXVuK2R5blZMeWR1R1NyVTdZSGQzblVhWld0K1NjRytGTTBRR29oUS9rd0lEQVFBQg0KQW9HQUR0VnM4bjBTOWtmNXRmdU9TZUhyVmcrM2FQK2x4SjJYd2VmN2JMZS9jVjZIZnRXbUxucGxpdzYzbVdKWg0KRUcyTHJBbXZVeUUwUVQ5S0NSTFhmMThTTVFjYUltbUZpY0JZOFMreXFnMGlMWnBuWXlPZEhBa1dOUUpHcHI2aQ0KYnVCbzkvajFFTTJWb0dUZ25nSXVxR3VQRy9qRWgrSmk3UlVCSHZnQXVsV0t4VUVDUVFETFF0SmxvdGFVSGdqWg0KRklBYmxTUk1nT3RVVFlnNHhpOU8zVnBQQVFSUlFtOFR2d2JkSWdPLzBYR0xrdTdPVFlmc21DMjkxckR0S3AwZQ0KQUY2M2Z4ZW5Ba0VBd25qU3NMYkdGTlhMSGdDQkJvcWd5WWhqSDB5OWg5dWxtSDREak95QkVLRWIvZ3lpaDVNZQ0Kb0VmRW5Nb0tjcUZWMWI1Vk5uU1NlSnVZcXVoN0dPUVdOUUpBVmVFejJER0hEQ25zZnh2RVRPTWs1UllMV0NFeQ0KRHhyZFhpcjBQekVreTlpUDZmM3FQb0JpcVNjckhGZkdnbkFMb0JGa01qT0ZxWTg1dHpWY3o1YnBQUUpCQU1DUA0Kbktmb1F4a01YUlIzRVV0bDV6SEcvOGRWV0hKMjluQ1pqbkJ6R3BWWndmcjdqYy9LeUUrUzRNY1RjK2J2ZzZ1aQ0KeklPZ1NBeHVuV3ZWeVZYck8yVUNRSCtCMmNWblRCUHYrU284bndEdjU1N2dHamxlcEdVakI4dXBnUDhxbnZSQg0KQ1VodEZpMEZ5UzN4cFRFR2J1Z0Z6T1ZzeUc5aERHMmRsc3dka1RvLzFJaz0NCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t".trim();

            String b64EncryptedStr  = "O1o3V6goj2w1YhpDXbBPb2tdtcIlYOUex4pw0f8Sc2TS8F6nSPpB15ODh86TVm6A5X7ZvgxbHn2hY4bQw5DS0Uu90ymrPHPAkvYBcaWLZruMv/mNzL0y2ZkMJa5M8SZKhKwjsl1mx/aW/6qZh3eZIb49CMlDK5L/m6OEqIRlTIg=".trim();

            System.out.println("PrivateKey (b64): " + b64PrivateKey);
            System.out.println(" Encrypted (b64): " + b64EncryptedStr);

            byte[] decodedKey           = decoder.decodeBuffer(b64PrivateKey);
            byte[] decodedStr           = decoder.decodeBuffer(b64EncryptedStr);
            PrivateKey privateKey       = strToPrivateKey(new String(decodedKey));

            Cipher cipher               = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);


            byte[] plainText            = cipher.doFinal(decodedStr);

            System.out.println("         Message: " + new String(plainText));
        }
        catch( Exception e )
        {
            System.out.println("           Error: " + e.getMessage());
        }

    }

    private static PrivateKey strToPrivateKey(String s)
    {
        try {
            BufferedReader br   = new BufferedReader( new StringReader(s) );
            PEMReader pr        = new PEMReader(br);
            KeyPair kp          = (KeyPair)pr.readObject();
            pr.close();
            return kp.getPrivate();
        }
        catch( Exception ignored)
        {

        }

        return null;
    }
}