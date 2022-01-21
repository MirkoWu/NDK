//
// Created by zhitao on 2016-08-16 16:52.
//

#include <sys/system_properties.h>
#include <malloc.h>
#include "SystemProp.h"


#ifdef DEBUG_LOG


#include "AndroidLog.h"


#endif

SystemProp::SystemProp() {

}

jstring SystemProp::getSystemProp(JNIEnv *env, jstring key_) {
	const char *key = env->GetStringUTFChars(key_, 0);
	if (key == NULL) {
		#ifdef DEBUG_LOG
		LOGE("内存溢出，没法获取system prop : %s", key);
		#endif
		return NULL;
	}

	// 定义一个接受结果的变量
	char value[PROP_VALUE_MAX];

	// 调用方法将结果写入到之前定义的变量中
	// 如果能读取到key的话就会不等于0,else 0
	int result = __system_property_get(key, value);
	env->ReleaseStringUTFChars(key_, key);

	if (result != 0) {
		return env->NewStringUTF(value);
	} else {
		return env->NewStringUTF(NULL);
	}
}

char *SystemProp::get_prop(const char *key) {

	char *value = (char *) malloc((PROP_VALUE_MAX + 1) * sizeof(char));
	if (value == NULL) {
		return NULL;
	}
	// 调用方法将结果写入到之前定义的变量中
	// 如果能读取到key的话就会不等于0,else 0
	int result = __system_property_get(key, value);
	return result != 0 ? value : NULL;
}

string SystemProp::get_prop(string key) {
	char *value = (char *) malloc((PROP_VALUE_MAX + 1) * sizeof(char));
	if (value == NULL) {
		return "";
	}
	// 调用方法将结果写入到之前定义的变量中
	// 如果能读取到key的话就会不等于0,else 0
	int result = __system_property_get(key.c_str(), value);
	if (result == 0) {
		return "";
	}
	string str = string(value);
	free(value);
	return str;
}