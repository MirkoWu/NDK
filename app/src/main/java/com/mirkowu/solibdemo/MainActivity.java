package com.mirkowu.solibdemo;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.pm.Signature;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.TextView;

import com.mirkowu.lib_util.LogUtil;
import com.mirkowu.lib_util.utilcode.util.AppUtils;
import com.mirkowu.lib_util.utilcode.util.ConvertUtils;
import com.mirkowu.lib_util.utilcode.util.EncryptUtils;
import com.mirkowu.ndk.NDKUtils;
import com.mirkowu.solibdemo.databinding.ActivityMainBinding;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
//    static {
//        System.loadLibrary("native-lib");
//    }

    public static final String PRO_BOARD = "ro.product.board";
    public static final String PRO_BRAND = "ro.product.brand";
    public static final String PRO_MODEL = "ro.product.model";
    public static final String PRO_PRODUCT = "ro.product.name";
    public static final String PRO_DEVICE = "ro.product.device";
    public static final String PRO_MANUFACTURER = "ro.product.manufacturer";
    public static final String PRO_BOOT = "ro.bootloader";
    public static final String PRO_HARDWARE = "ro.hardware";
    //public static final String PRO_FINGERPRINT = "ro.build.fingerprint";
    public static final String PRO_BASEBAND = "gsm.version.baseband";
    public static final String PRO_FLAVOR = "ro.build.flavor";
    public static final String PRO_PLATFORM = "ro.board.platform";

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());


        LogUtil.init(BuildConfig.DEBUG);
//        LogUtil.e("getAppSignatures getSign= " + NDKUtils.getSign(this));
        LogUtil.e("getAppSignatures byte= " + ConvertUtils.bytes2HexString(AppUtils.getAppSignatures()[0].toByteArray()));
        LogUtil.e("getAppSignaturesMD5= " + getSignatureString(AppUtils.getAppSignatures()[0], "MD5"));
        LogUtil.e("getAppSignaturesSHA1= " + getSignatureString(AppUtils.getAppSignatures()[0], "SHA1"));
        LogUtil.e("getAppSignatures NDKUtils= " + NDKUtils.e(this,"1234567812345678"));
//        LogUtil.e("getAppSignatures NDKUtils= " + NDKUtils.d(this,"JHGTxoFx/o0XG2cxoQ9iwmz2oxWl8DVFiZ9mWIKQCHE="));
//        LogUtil.e("getAppSignatures NDKUtils= " + NDKUtils.ek(this,"1234567812345678","1234567812345678"));
//        LogUtil.e("getAppSignatures NDKUtils= " + NDKUtils.dk(this,"bawcVudH+uA6z4xokeQo4NlqpCtZFRqem1kl/J2Vra8=","1234567812345678"));
//        LogUtil.e("getAppSignatures NDKUtils cbc_ek = " + NDKUtils.cbc_ek(this, "1234567812345678", "1234567812345678", "1234567812345678"));
////        LogUtil.e("getAppSignatures NDKUtils cbc_dk = " + NDKUtils.cbc_dk(this, "9AE8FD02B340288A0E7BBFF0F0BA54D674BF2EE1DC05F69500B4CAA70CDE416D", "1234567812345678", "1234567812345678"));
//
//        String data = "fse6g4segs5eg156s6+^#&@**$#(%UGNE(HG#g2jg0jjngn1234567812345678";
//        StringBuilder sb = new StringBuilder();
//        for (int i = 0; i < 100; i++) {
//            sb.append(data);
//        }
//        data = sb.toString();
//        String en = EncryptUtils.encryptAES2HexString(data.getBytes(), "1234567812345678".getBytes(),
//                "AES/ECB/PKCS5Padding", "1234567812345678".getBytes());
//        boolean same = TextUtils.equals(NDKUtils.dk(this, en, "1234567812345678"), data);
//        LogUtil.e("getAppSignatures NDKUtils cbc_dk = " + same);
//
//        String dc = new String(EncryptUtils.decryptHexStringAES(en , "1234567812345678".getBytes(),
//                "AES/ECB/PKCS5Padding", "1234567812345678".getBytes()));
//          same = TextUtils.equals(dc, data);
//        LogUtil.e("getAppSignatures NDKUtils cbc_dk = " + same);

//        LogUtil.e("getAppSignatures NDKUtils cbc_dk = " + NDKUtils.cbc_dk(this, "9AE8FD02B340288A0E7BBFF0F0BA54D674BF2EE1DC05F69500B4CAA70CDE416D", "1234567812345678", "1234567812345678"));
//
//
//        LogUtil.e("getAppSignatures NDKUtils= " + new String());
//        LogUtil.e("getAppSignatures NDKUtils= " + new String(EncryptUtils.decryptHexStringAES("9ae8fd02b340288a0e7bbff0f0ba54d674bf2ee1dc05f69500b4caa70cde416d" , "1234567812345678".getBytes(),
//                "AES/CBC/PKCS5Padding", "1234567812345678".getBytes())));
////        LogUtil.e("getAppSignatures NDKUtils= " + new String(EncryptUtils.decryptBase64AES("JHGTxoFx/o0XG2cxoQ9iwmz2oxWl8DVFiZ9mWIKQCHE=".getBytes(), "1234567812345678".getBytes(),
//                "AES/CBC/PKCS5Padding", "1234567812345678".getBytes())));

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(NDKUtils.checkSign(this) + " " + NDKUtils.getSystemProperty(PRO_BRAND));
//        tv.setText(NDKUtils.checkSign(this) + " " + NDKUtils.getSystemProperty2(PRO_BRAND));

        data = "fse6g4segs5eg156s6+^#&@**$#(%UGNE(HG#g2jg0jjngn1234567812345678";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100000; i++) {
            sb.append(data);
        }
        data = sb.toString();
        LogUtil.e(" getAppSignatures NDKUtils 数据构造完 ");
    }

    String data;

    /**
     * 获取相应的类型的字符串（把签名的byte[]信息转换成16进制）
     *
     * @param sig
     * @param type
     * @return
     */
    public static String getSignatureString(Signature sig, String type) {
        byte[] hexBytes = sig.toByteArray();
        String fingerprint = "error!";
        try {
            MessageDigest digest = MessageDigest.getInstance(type);
            if (digest != null) {
                byte[] digestBytes = digest.digest(hexBytes);
                StringBuilder sb = new StringBuilder();
                for (byte digestByte : digestBytes) {
                    sb.append((Integer.toHexString((digestByte & 0xFF) | 0x100)).substring(1, 3));
                }
                fingerprint = sb.toString();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return fingerprint;
    }

    public static String getSignatureString2(Signature sig, String type) {
        byte[] hexBytes = sig.toByteArray();
        String fingerprint = "error!";
        try {
            MessageDigest digest = MessageDigest.getInstance(type);
            if (digest != null) {
                byte[] digestBytes = digest.digest(hexBytes);
                StringBuilder sb = new StringBuilder();
                for (byte digestByte : digestBytes) {
                    sb.append((Integer.toHexString((digestByte & 0xFF) | 0x100)).substring(1, 3));
                }
                fingerprint = sb.toString();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return fingerprint;
    }

    public void clickTest(View view) {
        MainActivity context = MainActivity.this;
        final int[] count = {0};
        for (int j = 0; j < 100; j++) {
            //  int finalJ = j;
            new Thread(new Runnable() {
                @Override
                public void run() {


                    LogUtil.e("getAppSignatures NDKUtils cbc_dk  start----- ");
                    String data = "fse6g4segs5eg156s6+^#&@**$#(%UGNE(HG#g2jg0jjngn1234567812345678fse6g4segs5eg156s6+^#&@**$#(%UGNE(HG#g2jg0jjngn1234567812345678fse6g4segs5eg156s6+^#&@**$#(%UGNE(HG#g2jg0jjngn1234567812345678fse6g4segs5eg156s6+^#&@**$#(%UGNE(HG#g2jg0jjngn1234567812345678fse6g4segs5eg156s6+^#&@**$#(%UGNE(HG#g2jg0jjngn1234567812345678fse6g4segs5eg156s6+^#&@**$#(%UGNE(HG#g2jg0jjngn1234567812345678fse6g4segs5eg156s6+^#&@**$#(%UGNE(HG#g2jg0jjngn1234567812345678";

                    String ecb= new String(EncryptUtils.encrypt3DES2Base64(data.getBytes(), "1234567812345678".getBytes(), "AES/ECB/PKCS5Padding", null));


                    String en = EncryptUtils.encryptAES2HexString(data.getBytes(), "1234567812345678".getBytes(),
                            "AES/CBC/PKCS5Padding", "1234567812345678".getBytes());
                    String en_ndk = NDKUtils.cbc_ek(context, data, "1234567812345678", "1234567812345678");
                    boolean same = TextUtils.equals(NDKUtils.cbc_dk(context, en, "1234567812345678", "1234567812345678"), data);
                    count[0]++;

                    LogUtil.e(count[0] + "getAppSignatures ecb加密相等= " + ecb.equalsIgnoreCase(NDKUtils.ek(context, data,"1234567812345678")));
                    LogUtil.e(count[0] + "getAppSignatures ecb解密相等= " + data.equalsIgnoreCase(NDKUtils.dk(context, ecb,"1234567812345678")));


                    LogUtil.e(count[0] + " getAppSignatures NDKUtils 加密相等 = " + en.equalsIgnoreCase(en_ndk));
                    LogUtil.e(count[0] + " getAppSignatures NDKUtils cbc_dk = " + same);

                }

            }).start();
        }

    }
}