/*
 * utils.h
 *
 *  Created on: 2014Äê4ÔÂ2ÈÕ
 *      Author: auxten
 */

#ifndef UTILS_H_
#define UTILS_H_

#ifdef __ANDROID__
#include "dlog.h"
#else
#include "src/utils.h"
#endif // __ANDROID__


/// Macros for min/max.
#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif /** MIN **/
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif  /** MAX **/


#define SAFE_FREE(addr) do{if(addr){LOGD("Free "#addr);free(addr);}addr=NULL;}while(0)
#define SAFE_CLOSE(fd) do{if(fd >= 0)close(fd);fd=-1;}while(0)
#define SAFE_CLOSE_FP(fp) do{if(fp)fclose(fp);fp=NULL;}while(0)


#endif /* UTILS_H_ */
