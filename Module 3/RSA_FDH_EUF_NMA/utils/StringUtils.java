package utils;

import java.util.Random;
import java.security.SecureRandom;

/**
 * util class for strings
 * 
 * @author Julia
 */
public class StringUtils {
    /**
     * Generates a random string, for example to be used as a message. The generated
     * string will mostly contain printable characters.
     * 
     * @param RNG    a random number generator whose randomness shall be used.
     * @param length the length of the string to be outputted.
     * @return a string of the length you specified.
     */
    public static String generateRandomString(Random RNG, int length) {
        var bytes = new byte[length];
        RNG.nextBytes(bytes);

        // String ret = new String(bytes, Charset.forName("UTF-8")); this works, but
        // gives a lot of problematic characters

        var chars = new char[length];
        char lowerBound = (char) Math.min(Math.min('a', 'A'), '0');
        char upperBound = (char) Math.max(Math.max('z', 'Z'), '9');
        for (int i = 0; i < bytes.length; i++) {
            double t = (bytes[i] + 128.0) / 255; // t lies in [0, 1]
            double n = lowerBound + (upperBound - lowerBound) * t; // n lies in [lowerBound, upperBound];
            chars[i] = (char) n;
        }
        String ret = new String(chars);
        return ret;
    }

    /**
     * Demonstration Code for generateRandomString.
     * 
     * @param args
     */
    public static void main(String[] args) {
        var RNG = new SecureRandom();
        for (int i = 0; i < 20; i++) {
            System.out.println(generateRandomString(RNG, i));
        }
    }
}
