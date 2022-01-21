#include <jni.h>
#include <string>
#include "aes_utils.h"
#include "constchar.h"
#include "hex_utils.h"
#include "SystemProp.h"
#include "junk.h"
#include <android/log.h>
#include <assert.h>
#include <pthread.h>


#define CheckSign  abcd
#define Encrypt  aaa
#define Decrypt  bbb
#define EncryptWithKey  ccc
#define DecryptWithKey  ddd
//#define getKey                     bc
//#define getIV                      bd
//#define BID  ddd
//#define SPK  eee

//LOG宏定义
#define LOG_TAG  "JNI_SCRIPT"
#define LOG_E(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
const char *RELEASE_SIGN = "30820301308201e9a003020102020438ab872a300d06092a864886f70d01010b05003030310e300c060355040a13056d69726b6f310e300c060355040b13056d69726b6f310e300c060355040313056d69726b6f3020170d3230303532353032333230375a180f32313238303432393032333230375a3030310e300c060355040a13056d69726b6f310e300c060355040b13056d69726b6f310e300c060355040313056d69726b6f30820122300d06092a864886f70d01010105000382010f003082010a02820101009f31dc32fde7c34d3a9c6d7c2a5d39ae16cc124e92d6819aff8eeb0afeb1eba4eb422377b38a51d5e0b115cf37e71e957398b56d39a42b9a70228c691a44d54926384f81ec159637f89008cbe6956dc6dc1e8978ec74614f1b8f06d9393c3b029981eefb41670e9c4f84a34efa475b66ff8aec37189f010cac332a5b78f1e81fdfc0f14cbdc0838e83a2b31477cb1de37bf6f11a68f0e00bdb26a5d517eb5834509c000ca2dd3e9116eec3dbde12270cb146cb99fc0f63cb0817e74c20d023958eba0411f9dd011f24cbcaa1686d17ca2efc6a04d83b40dfef20c5965690f558dc16f7762a53afe67022d93cd6910aebc8d542adb0a0a45cd352552b8c0528550203010001a321301f301d0603551d0e04160414389686aef8fd6c6b0cff4070d36b6b0ecd70a638300d06092a864886f70d01010b050003820101006b4529c343748c14ef076f56a56d27cfe604a346c24ec175b6a2920c3ea6ccd59da5221d7c650370bab2c61037245c20f1dcf98b5419f2fc2f064de27ad4efbb3958ef21396cc606be2109c23dcfc19490b6650cee29691c6cc91df40ef11eae8c14bcca8243012cfcd75b4146c4f177c43833fd0a0185f6ae8e1b10f6685ff855932ec8373c3b22bce673acd44e4fb2ba51a1c8de07cba9c3973c621ae53f5d440b49c9a3593a3390b371382afe9cc16f3ea8c6f211fddb878c45134d08e9653c3902dad6779d35c59b19110ef8eb4ba7f0596a890666b0946dfc9925a7b0fac982b60d798b8a88464fcd39e3f82ab790c0630ea5dba09ba5ced12763d30dc5";
//const char *pkg = "com.mirkowu.xxx"; //当前程序包名
const char *error = "error sign";
const char *KEY = "1234567812345678";

pthread_mutex_t mutex;//线程锁

/**
 * 校验包名和签名
 * 获取签名方式：ConvertUtils.bytes2HexString(AppUtils.getAppSignatures()[0].toByteArray())
 */
extern "C"
JNIEXPORT jboolean JNICALL
CheckSign(JNIEnv *env, jclass type, jobject ctx) {
    //根据传入的context对象获取getApplicationContext()，防止java中获取其它已安装APK的Context对象
    jclass context_cls = env->GetObjectClass(ctx);
    jmethodID applicationContextMethod = env->GetMethodID(context_cls,
                                                          "getApplicationContext",
                                                          "()Landroid/content/Context;");
    jobject applicationContext = env->CallObjectMethod(ctx,
                                                       applicationContextMethod);
    if (applicationContext == NULL) {
        LOG_E("context invalid!!");
        return false;
    }

//    //根据传入的context对象getPackageName
//    jmethodID pkgName_method = env->GetMethodID(context_cls, "getPackageName",
//                                                "()Ljava/lang/String;");
//    jstring pkgName = static_cast<jstring>(env->CallObjectMethod(applicationContext,
//                                                                 pkgName_method));
//    const char *pkgChar = env->GetStringUTFChars(pkgName, NULL);
//    //对比程序包名
//    if (strcmp(pkg, pkgChar) != 0) {
//        LOG_E("package name invalid!!");
//        return false;
//    }


    jclass native_class = env->GetObjectClass(ctx);
    jmethodID pm_id = env->GetMethodID(native_class, "getPackageManager",
                                       "()Landroid/content/pm/PackageManager;");
    jobject pm_obj = env->CallObjectMethod(ctx, pm_id);
    jclass pm_clazz = env->GetObjectClass(pm_obj);
    // 得到 getPackageInfo 方法的 ID
    jmethodID package_info_id = env->GetMethodID(pm_clazz, "getPackageInfo",
                                                 "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jclass native_classs = env->GetObjectClass(ctx);
    jmethodID mId = env->GetMethodID(native_classs, "getPackageName",
                                     "()Ljava/lang/String;");
    //static_cast<jstring>
    jstring pkg_str = static_cast<jstring>(env->CallObjectMethod(ctx, mId));
    // 获得应用包的信息
    jobject pi_obj = env->CallObjectMethod(pm_obj, package_info_id, pkg_str, 64);
    // 获得 PackageInfo 类
    jclass pi_clazz = env->GetObjectClass(pi_obj);
    // 获得签名数组属性的 ID
    jfieldID signatures_fieldId = env->GetFieldID(pi_clazz, "signatures",
                                                  "[Landroid/content/pm/Signature;");
    jobject signatures_obj = env->GetObjectField(pi_obj, signatures_fieldId);
    jobjectArray signaturesArray = (jobjectArray) signatures_obj;
    //jsize size = env->GetArrayLength(signaturesArray);
    jobject signature_obj = env->GetObjectArrayElement(signaturesArray, 0);
    jclass signature_clazz = env->GetObjectClass(signature_obj);
    jmethodID string_id = env->GetMethodID(signature_clazz, "toCharsString",
                                           "()Ljava/lang/String;");
    //static_cast<jstring>
    jstring str = static_cast<jstring>(env->CallObjectMethod(signature_obj, string_id));
    const char *c_msg = env->GetStringUTFChars(str, 0);

    return strcmp(c_msg, RELEASE_SIGN) == 0;

}
//jstring charToJstring(JNIEnv *envPtr, char *src) {
//    JNIEnv env = *envPtr;
//
//    jsize len = strlen(src);
//    jclass pi_clazz = env->GetObjectClass(pi_obj);
//    jclass clsstring = env->FindClass(envPtr, "java/lang/String");
//    jstring strencode = env->NewStringUTF(envPtr, "UTF-8");
//    jmethodID mid = env->GetMethodID(envPtr, clsstring, "<init>",
//                                     "([BLjava/lang/String;)V");
//    jbyteArray barr = env->NewByteArray(envPtr, len);
//    env->SetByteArrayRegion(envPtr, barr, 0, len, (jbyte *) src);
//
//    return (jstring) env->NewObject(envPtr, clsstring, mid, barr, strencode);
//}



// key: mirkoancnac@meng
uint8_t *getKey() {
    _JUNK_FUN_0
    uint8_t *src = static_cast<uint8_t *>(malloc(17));//尾部多一位 \0
//    uint8_t src[17];//尾部多一位 \0

    src[0] = m;
    src[1] = i;
    src[2] = r;
    src[3] = k;
    src[4] = o;
    src[5] = a;
    src[6] = n;
    src[7] = c;
    src[8] = n;
    src[9] = a;
    src[10] = c;
    src[11] = c8;
    src[12] = m;
    src[13] = e;
    src[14] = n;
    src[15] = g;
    src[16] = '\0';
    _JUNK_FUN_1
    return src;
}

//// iv: mirkoancnac@meng
//uint8_t *getIV() {
//    _JUNK_FUN_2
//    uint8_t *src = static_cast<uint8_t *>(malloc(17));//尾部多一位 \0
//    src[0] = m;
//    src[1] = i;
//    src[2] = r;
//    src[3] = k;
//    src[4] = o;
//    src[5] = a;
//    src[6] = n;
//    src[7] = c;
//    src[8] = n;
//    src[9] = a;
//    src[10] = c;
//    src[11] = c8;
//    src[12] = m;
//    src[13] = e;
//    src[14] = n;
//    src[15] = g;
//
//    src[16] = '\0';
//    _JUNK_FUN_2
//    return src;
//}

//
//extern "C"
//jstring JNICALL
//BID(JNIEnv *env) {
//    char key[33];//尾部多一位 \0
//    // 04de7fe0d42c86fb8d39af5768958d53
//
//    key[0] = n0;
//    key[1] = n4;
//    key[2] = d;
//    key[3] = e;
//    key[4] = n7;
//    key[5] = f;
//    key[6] = e;
//    key[7] = n0;
//    key[8] = d;
//    key[9] = n4;
//    key[10] = n2;
//    key[11] = c;
//    key[12] = n8;
//    key[13] = n6;
//    key[14] = f;
//    key[15] = b;
//    key[16] = n8;
//    key[17] = d;
//    key[18] = n3;
//    key[19] = n9;
//    key[20] = a;
//    key[21] = f;
//    key[22] = n5;
//    key[23] = n7;
//    key[24] = n6;
//    key[25] = n8;
//    key[26] = n9;
//    key[27] = n5;
//    key[28] = n8;
//    key[29] = d;
//    key[30] = n5;
//    key[31] = n3;
//    key[32] = '\0';
//
//    return env->NewStringUTF(key);
//}
//
//jstring JNICALL
//SPK(JNIEnv *env) {
//    char key[17];//尾部多一位 \0
//
//    key[0] = j;
//    key[1] = i;
//    key[2] = g;
//    key[3] = o;
//    key[4] = s;
//    key[5] = r;
//    key[6] = e;
//    key[7] = j;
//    key[8] = i;
//    key[9] = n3;
//    key[10] = n2;
//    key[11] = i;
//    key[12] = n2;
//    key[13] = G;
//    key[14] = c8;
//    key[15] = n2;
//    key[16] = '\0';
//    return env->NewStringUTF(key);
//}


extern "C"
JNIEXPORT jstring JNICALL
Encrypt(JNIEnv *env, jclass type, jobject cxt, jstring str_) {
//    pthread_mutex_lock(&mutex);//并发 这里要加锁

    if (CheckSign(env, type, cxt)) {
        const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
        uint8_t *key = getKey();
        char *result = AES_128_ECB_PKCS5_Encrypt(str, key);
        env->ReleaseStringUTFChars(str_, str);

        jstring jResult = env->NewStringUTF(result);
        free(key);
        free(result);

 //       pthread_mutex_unlock(&mutex);//释放锁

        return jResult;
    } else {

  //      pthread_mutex_unlock(&mutex);//释放锁

        return env->NewStringUTF(error);
    }
}

extern "C"
JNIEXPORT jstring JNICALL
EncryptWithKey(JNIEnv *env, jclass type, jobject cxt, jstring str_, jstring key_) {
//    pthread_mutex_lock(&mutex);//并发 这里要加锁

    if (CheckSign(env, type, cxt)) {
        const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
        const char *key = env->GetStringUTFChars(key_, JNI_FALSE);
        char *result = AES_128_ECB_PKCS5_Encrypt(str, (uint8_t *) key);
        env->ReleaseStringUTFChars(str_, str);
        env->ReleaseStringUTFChars(key_, key);

        jstring jResult = env->NewStringUTF(result);
        free(result);
//        free(  key);

//        pthread_mutex_unlock(&mutex);//释放锁

        return jResult;
    } else {

 //       pthread_mutex_unlock(&mutex);//释放锁

        return env->NewStringUTF(error);
    }
}

extern "C"
JNIEXPORT jstring JNICALL
AES_CBC_PKCS5_Encrypt(JNIEnv *env, jclass type, jobject cxt, jstring str_, jstring key_, jstring iv_) {
 //   pthread_mutex_lock(&mutex);//并发 这里要加锁

    if (CheckSign(env, type, cxt)) {
        const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
        const char *key = env->GetStringUTFChars(key_, JNI_FALSE);
        const char *iv = env->GetStringUTFChars(iv_, JNI_FALSE);
        char *result = AES_128_CBC_PKCS5_Encrypt(str, (uint8_t *) key, (uint8_t *) iv);
        env->ReleaseStringUTFChars(str_, str);
        env->ReleaseStringUTFChars(key_, key);
        env->ReleaseStringUTFChars(iv_, iv);

        jstring jResult = env->NewStringUTF(result);
        free(result);

 //       pthread_mutex_unlock(&mutex);//释放锁

        return jResult;
    } else {

 //       pthread_mutex_unlock(&mutex);//释放锁

        return env->NewStringUTF(error);
    }
}


extern "C"
jstring JNICALL
Decrypt(JNIEnv *env, jclass type, jobject cxt, jstring str_) {
 //   pthread_mutex_lock(&mutex);//多个请求 这里要加锁

    if (CheckSign(env, type, cxt)) {
        const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
        uint8_t *key = getKey();
        char *result = AES_128_ECB_PKCS5_Decrypt(str, (uint8_t *) key);
        env->ReleaseStringUTFChars(str_, str);

        jstring jResult = env->NewStringUTF(result);
        free(key);
        free(result);

        pthread_mutex_unlock(&mutex);//释放锁

        return jResult;
    } else {
 //       pthread_mutex_unlock(&mutex);//释放锁

        return env->NewStringUTF(error);
    }
}

extern "C"
jstring JNICALL
DecryptWithKey(JNIEnv *env, jclass type, jobject cxt, jstring str_, jstring key_) {
 //   pthread_mutex_lock(&mutex);//多个请求 这里要加锁

    if (CheckSign(env, type, cxt)) {
        const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
        const char *key = env->GetStringUTFChars(key_, JNI_FALSE);
        char *result = AES_128_ECB_PKCS5_Decrypt(str, (uint8_t *) key);
        env->ReleaseStringUTFChars(str_, str);
        env->ReleaseStringUTFChars(key_, key);

        jstring jResult = env->NewStringUTF(result);
        free(result);

      //  pthread_mutex_unlock(&mutex);//释放锁

        return jResult;
    } else {
      //  pthread_mutex_unlock(&mutex);//释放锁

        return env->NewStringUTF(error);
    }
}

extern "C"
jstring JNICALL
AES_CBC_PKCS5_Decrypt(JNIEnv *env, jclass type, jobject cxt, jstring str_, jstring key_, jstring iv_) {
 //   pthread_mutex_lock(&mutex);//多个请求 这里要加锁

    if (CheckSign(env, type, cxt)) {
        const char *str = env->GetStringUTFChars(str_, JNI_FALSE);
        const char *key = env->GetStringUTFChars(key_, JNI_FALSE);
        const char *iv = env->GetStringUTFChars(iv_, JNI_FALSE);
        char *result = AES_128_CBC_PKCS5_Decrypt(str, (uint8_t *) key, (uint8_t *) iv);
        env->ReleaseStringUTFChars(str_, str);
        env->ReleaseStringUTFChars(key_, key);
        env->ReleaseStringUTFChars(iv_, iv);
        jstring jResult = env->NewStringUTF(result);
        free(result);

//        pthread_mutex_unlock(&mutex);//释放锁
        return jResult;
    } else {
  //      pthread_mutex_unlock(&mutex);//释放锁

        return env->NewStringUTF(error);
    }
}
//获取系统参数
extern "C"
jstring JNICALL
GetSystemProperty(JNIEnv *env, jclass type, jstring jsKey) {
    const char *key = env->GetStringUTFChars(jsKey, JNI_FALSE);
    char *value = SystemProp::get_prop(key);
    env->ReleaseStringUTFChars(jsKey, key);
    jstring jResult = env->NewStringUTF(value);
    free(value);
    return jResult;
}

//extern "C"
//jstring JNICALL
//getAK(JNIEnv *env, jclass type, jobject cxt) {
//    if (CheckSign(env, type, cxt)) {
//        const char *s = getKey();
//        return env->NewStringUTF(s);
//    } else {
//        return env->NewStringUTF(error);
//    }
//}
//
//extern "C"
//jstring JNICALL
//getAI(JNIEnv *env, jclass type, jobject cxt) {
//    if (CheckSign(env, type, cxt)) {
//        const char *s = getIV();
//        return env->NewStringUTF(s);
//    } else {
//        return env->NewStringUTF(error);
//    }
//}

//extern "C"
//jstring JNICALL
//getBID(JNIEnv *env, jclass type, jobject cxt) {
//    if (CheckSign(env, type, cxt)) {
//        //const u_int8_t *s = BID(env);
//        return BID(env);
//    } else {
//        return env->NewStringUTF(error);
//    }
//}

//jstring JNICALL
//getSPK(JNIEnv *env, jclass type, jobject cxt) {
//    if (CheckSign(env, type, cxt)) {
//        return SPK(env);
//    } else {
//        return env->NewStringUTF(error);
//    }
//}



/**
 * ------------------------ 以下是 动态注册 -----------------------------------------------
 */






/**
 * 所谓的动态注册 是指，动态注册JAVA的Native方法，使得c/c++里面方法名 可以和 java 的Native方法名可以不同，
 * 动态注册是将将二者方法名关联起来，以后在修改Native方法名时，只需修改动态注册关联的方法名称即可
 *  System.loadLibrary("xxx"); 这个方法还是必须要调用的，不管动态还是静态
 */
#define JNIREG_CLASS "com/mirkowu/ndk/NDKUtils"  //路径：包名+类名
#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))


static JNINativeMethod method_table[] = {
        // 第一个值a 是native方法名，
        // 第二个值 是native方法参数,括号里面是传入参的类型，外边的是返回值类型，
        // 第三个值 是c/c++方法参数,括号里面是返回值类型，
        {"checkSign",         "(Ljava/lang/Object;)Z",                                                      (jboolean *) abcd},
        {"getSystemProperty", "(Ljava/lang/String;)Ljava/lang/String;",                                     (jstring *) GetSystemProperty},

        {"e",                 "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;",                   (jstring *) aaa},
        {"d",                 "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;",                   (jstring *) bbb},
        {"ek",                "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (jstring *) ccc},
        {"dk",                "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (jstring *) ddd},
        {"cbc_ek",                "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (jstring *) AES_CBC_PKCS5_Encrypt},
        {"cbc_dk",                "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (jstring *) AES_CBC_PKCS5_Decrypt},

        //没必要开放key
//        {"getAK",             "(Ljava/lang/Object;)Ljava/lang/String;",                                     (jstring *) getAK},
};

static int registerMethods(JNIEnv *env, const char *className,
                           JNINativeMethod *gMethods, int numMethods) {
    jclass clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}


extern "C"
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    //LOG_E("JNI_OnLoad  JNI_OnLoad");
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        //LOG_E("JNI_OnLoad  GetEnv");
        return JNI_ERR;
    }
    assert(env != NULL);

    // 注册native方法
    if (!registerMethods(env, JNIREG_CLASS, method_table, NELEM(method_table))) {
        //LOG_E("JNI_OnLoad  registerMethods");
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
