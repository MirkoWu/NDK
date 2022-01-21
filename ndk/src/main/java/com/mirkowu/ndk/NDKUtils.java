package com.mirkowu.ndk;

public class NDKUtils {
    static {
        System.loadLibrary("ndkutils");
    }

    public static native boolean checkSign(Object cxt);

    public static native String getSystemProperty(String key);


    public static native String e(Object cxt, String str);

    public static native String d(Object cxt, String str);

    public static native String ek(Object cxt, String str, String key);

    public static native String dk(Object cxt, String str, String key);
    public static native String cbc_ek(Object cxt, String str, String key, String iv);
    public static native String cbc_dk(Object cxt, String str, String key, String iv);


}
