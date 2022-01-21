//
// Created by zhitao on 2016-08-16 16:52.
//

#ifndef YMDEV_SYSTEMPROP_H
#define YMDEV_SYSTEMPROP_H


#include <jni.h>
#include <string>

using std::string;

class SystemProp {
	public:
		SystemProp();
		
		static jstring getSystemProp(JNIEnv *env, jstring key_);

		/**
		 * 自行在外面free
		 */
		static char *get_prop(const char *key);

		static string get_prop(string key);

};


#endif //YMDEV_SYSTEMPROP_H
