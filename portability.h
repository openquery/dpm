/*
 *  Copyright 2008 Dormando (dormando@rydia.net).  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
*/

/* Copyright Abandoned 1996 TCX DataKonsult AB & Monty Program KB & Detron HB 
This file is public domain and comes with NO WARRANTY of any kind */

/*
  Parts of the original, which are not applicable to mysqlnd have been removed.
  
  With small modifications, mostly casting but adding few more macros by
  Andrey Hristov <andrey@mysql.com> . The additions are in the public domain and
  were added to improve the header file, to get it more consistent.
*/

#ifndef __attribute
#if !defined(__GNUC__)
#define __attribute(A)
#endif
#endif

#ifdef __CYGWIN__
/* We use a Unix API, so pretend it's not Windows */
#undef WIN
#undef WIN32
#undef _WIN
#undef _WIN32
#undef _WIN64
#undef __WIN__
#undef __WIN32__
#endif /* __CYGWIN__ */


#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
#include <ext/mysqli/mysqlnd/config-win.h>
#endif /* _WIN32... */


#if SIZEOF_LONG_LONG > 4 && !defined(_LONG_LONG)
#define _LONG_LONG 1        /* For AIX string library */
#endif


/* Some defines of functions for portability */

#ifndef HAVE_ATOD
#define atod        atof
#endif


#if SIZEOF_LONG_LONG > 4
#define HAVE_LONG_LONG 1
#endif

#if defined(HAVE_LONG_LONG) && !defined(LONGLONG_MIN)
#define LONGLONG_MIN    ((long long) 0x8000000000000000LL)
#define LONGLONG_MAX    ((long long) 0x7FFFFFFFFFFFFFFFLL)
#endif

#if SIZEOF_LONG == 4
#define INT_MIN32    (long) 0x80000000L
#define INT_MAX32    (long) 0x7FFFFFFFL
#define INT_MIN24    ((long) 0xff800000L)
#define INT_MAX24    0x007fffffL
#define INT_MIN16    ((short int) 0x8000)
#define INT_MAX16    0x7FFF
#define INT_MIN8    ((char) 0x80)
#define INT_MAX8    ((char) 0x7F)
#else  /* Probably Alpha */
#define INT_MIN32    ((long) (int) 0x80000000)
#define INT_MAX32    ((long) (int) 0x7FFFFFFF)
#define INT_MIN24    ((long) (int) 0xff800000)
#define INT_MAX24    ((long) (int) 0x007fffff)
#define INT_MIN16    ((short int) 0xffff8000)
#define INT_MAX16    ((short int) 0x00007FFF)
#endif


/* Typdefs for easyier portability */

#ifndef HAVE_INT_8_16_32
typedef char    int8;        /* Signed integer >= 8    bits */
typedef short    int16;        /* Signed integer >= 16 bits */
#endif
#ifndef HAVE_UCHAR
typedef unsigned char    uchar;    /* Short for unsigned char */
#endif
typedef unsigned char    uint8;    /* Short for unsigned integer >= 8  bits */
typedef unsigned short    uint16; /* Short for unsigned integer >= 16 bits */

#if SIZEOF_INT == 4
#ifndef HAVE_INT_8_16_32
typedef int        int32;
#endif
typedef unsigned int    uint32; /* Short for unsigned integer >= 32 bits */
#elif SIZEOF_LONG == 4
#ifndef HAVE_INT_8_16_32
typedef long        int32;
#endif
typedef unsigned long    uint32; /* Short for unsigned integer >= 32 bits */
#else
typedef uint32_t    uint32; /* see above :\ - Dormando */
#endif

#ifndef longlong_defined
#if defined(HAVE_LONG_LONG) && SIZEOF_LONG != 8
typedef unsigned long long int ulonglong; /* ulong or unsigned long long */
typedef long long int longlong;
#else
typedef unsigned long    ulonglong;    /* ulong or unsigned long long */
typedef long        longlong;
#endif
#endif


#if A0
#ifndef byte_defined
typedef char        byte;    /* Smallest addressable unit */
#endif
#endif

    /* Macros for converting *constants* to the right type */
#define INT8(v)      (int8) (v)
#define INT16(v)    (int16) (v)
#define INT32(v)    (int32) (v)


#define int1store(T,A)	do { *((unsigned char*) (T)) = (A); } while(0)
#define uint1korr(A)	(*(((unsigned char*)(A))))

/*
** Define-funktions for reading and storing in machine independent format
**  (low byte first)
*/

/* Optimized store functions for Intel x86, non-valid for WIN64 */
#if defined(__i386__) && !defined(_WIN64)
#define sint2korr(A)    (*((int16 *) (A)))
#define sint3korr(A)    ((int32) ((((uchar) (A)[2]) & 128) ? \
                  (((uint32) 255L << 24) | \
                   (((uint32) (uchar) (A)[2]) << 16) |\
                   (((uint32) (uchar) (A)[1]) << 8) | \
                    ((uint32) (uchar) (A)[0])) : \
                   (((uint32) (uchar) (A)[2]) << 16) |\
                   (((uint32) (uchar) (A)[1]) << 8) | \
                    ((uint32) (uchar) (A)[0])))
#define sint4korr(A)  (*((long *) (A)))
#define uint2korr(A)  (*((uint16 *) (A)))
#define uint3korr(A)  (uint32) (((uint32) ((uchar) (A)[0])) +\
                               (((uint32) ((uchar) (A)[1])) << 8) +\
                               (((uint32) ((uchar) (A)[2])) << 16))
#define uint4korr(A)  (*((unsigned long *) (A)))
#define uint5korr(A)  ((ulonglong)(((uint32) ((uchar) (A)[0])) +\
                                  (((uint32) ((uchar) (A)[1])) << 8) +\
                                  (((uint32) ((uchar) (A)[2])) << 16) +\
                                  (((uint32) ((uchar) (A)[3])) << 24)) +\
                               (((ulonglong) ((uchar) (A)[4])) << 32))
/* From Andrey Hristov, based on uint5korr() */
#define uint6korr(A)  ((ulonglong)(((uint32) ((uchar) (A)[0])) +\
                                  (((uint32) ((uchar) (A)[1])) << 8) +\
                                  (((uint32) ((uchar) (A)[2])) << 16) +\
                                  (((uint32) ((uchar) (A)[3])) << 24)) +\
                                  (((ulonglong) ((uchar) (A)[4])) << 32)) +\
                                  (((ulonglong) ((uchar) (A)[5])) << 40))
#define uint8korr(A)    (*((ulonglong *) (A)))
#define sint8korr(A)    (*((longlong *) (A)))
#define int2store(T,A)    *((uint16*) (T))= (uint16) (A)
#define int3store(T,A)   { \
                  *(T)=  (uchar) ((A));\
                  *(T+1)=(uchar) (((uint) (A) >> 8));\
                  *(T+2)=(uchar) (((A) >> 16)); }
#define int4store(T,A)    *((long *) (T))= (long) (A)
#define int5store(T,A)    { \
              *((uchar *)(T))= (uchar)((A));\
              *(((uchar *)(T))+1)=(uchar) (((A) >> 8));\
              *(((uchar *)(T))+2)=(uchar) (((A) >> 16));\
              *(((uchar *)(T))+3)=(uchar) (((A) >> 24)); \
              *(((uchar *)(T))+4)=(uchar) (((A) >> 32)); }

/* From Andrey Hristov, based on int5store() */
#define int6store(T,A)    { \
              *(((uchar *)(T)))= (uchar)((A));\
              *(((uchar *)(T))+1))=(uchar) (((A) >> 8));\
              *(((uchar *)(T))+2))=(uchar) (((A) >> 16));\
              *(((uchar *)(T))+3))=(uchar) (((A) >> 24)); \
              *(((uchar *)(T))+4))=(uchar) (((A) >> 32)); \
              *(((uchar *)(T))+5))=(uchar) (((A) >> 40)); }

#define int8store(T,A)    *((ulonglong *) (T))= (ulonglong) (A)

typedef union {
  double v;
  long m[2];
} doubleget_union;
#define doubleget(V,M)    { ((doubleget_union *)&(V))->m[0] = *((long*) (M)); \
                            ((doubleget_union *)&(V))->m[1] = *(((long*) (M))+1); }
#define doublestore(T,V) { *((long *) (T))     = ((doubleget_union *)&(V))->m[0]; \
                           *(((long *) (T))+1) = ((doubleget_union *)&(V))->m[1]; }
#define float4get(V,M) { *((float *) &(V)) = *((float*) (M)); }
#define float8get(V,M) doubleget((V),(M))
/* From Andrey Hristov based on doubleget */
#define floatget(V,M)    memcpy((char*) &(V),(char*) (M),sizeof(float))
#define floatstore       float4store
#define float4store(V,M) memcpy((char*) (V),(char*) (&M),sizeof(float))
#define float8store(V,M) doublestore((V),(M))
#endif /* __i386__ */ 

#ifndef sint2korr
#define sint2korr(A)    (int16) (((int16) ((uchar) (A)[0])) +\
                                 ((int16) ((int16) (A)[1]) << 8))
#define sint3korr(A)    ((int32) ((((uchar) (A)[2]) & 128) ? \
                  (((uint32) 255L << 24) | \
                  (((uint32) (uchar) (A)[2]) << 16) |\
                  (((uint32) (uchar) (A)[1]) << 8) | \
                   ((uint32) (uchar) (A)[0])) : \
                  (((uint32) (uchar) (A)[2]) << 16) |\
                  (((uint32) (uchar) (A)[1]) << 8) | \
                  ((uint32) (uchar) (A)[0])))
#define sint4korr(A)  (int32) (((int32) ((uchar) (A)[0])) +\
                              (((int32) ((uchar) (A)[1]) << 8)) +\
                              (((int32) ((uchar) (A)[2]) << 16)) +\
                              (((int32) ((int16) (A)[3]) << 24)))
#define sint8korr(A)  (longlong) uint8korr(A)
#define uint2korr(A)  (uint16) (((uint16) ((uchar) (A)[0])) +\
                               ((uint16) ((uchar) (A)[1]) << 8))
#define uint3korr(A)  (uint32) (((uint32) ((uchar) (A)[0])) +\
                               (((uint32) ((uchar) (A)[1])) << 8) +\
                               (((uint32) ((uchar) (A)[2])) << 16))
#define uint4korr(A)  (uint32) (((uint32) ((uchar) (A)[0])) +\
                               (((uint32) ((uchar) (A)[1])) << 8) +\
                               (((uint32) ((uchar) (A)[2])) << 16) +\
                               (((uint32) ((uchar) (A)[3])) << 24))
#define uint5korr(A)  ((ulonglong)(((uint32) ((uchar) (A)[0])) +\
                                  (((uint32) ((uchar) (A)[1])) << 8) +\
                                  (((uint32) ((uchar) (A)[2])) << 16) +\
                                  (((uint32) ((uchar) (A)[3])) << 24)) +\
                               (((ulonglong) ((uchar) (A)[4])) << 32))
/* From Andrey Hristov, based on uint5korr */
#define uint6korr(A)  ((ulonglong)(((uint32) ((uchar) (A)[0])) +\
                                  (((uint32) ((uchar) (A)[1])) << 8) +\
                                  (((uint32) ((uchar) (A)[2])) << 16) +\
                                  (((uint32) ((uchar) (A)[3])) << 24)) +\
                                  (((ulonglong) ((uchar) (A)[4])) << 32)) +\
                                  (((ulonglong) ((uchar) (A)[5])) << 40))
#define uint8korr(A)  ((ulonglong)(((uint32) ((uchar) (A)[0])) +\
                                  (((uint32) ((uchar) (A)[1])) << 8) +\
                                  (((uint32) ((uchar) (A)[2])) << 16) +\
                                  (((uint32) ((uchar) (A)[3])) << 24)) +\
                                  (((ulonglong) (((uint32) ((uchar) (A)[4])) +\
                                  (((uint32) ((uchar) (A)[5])) << 8) +\
                                  (((uint32) ((uchar) (A)[6])) << 16) +\
                                  (((uint32) ((uchar) (A)[7])) << 24))) << 32))
#define int2store(T,A)  do { uint def_temp= (uint) (A) ;\
                  *((uchar*) (T))  =  (uchar)(def_temp); \
                  *((uchar*) (T+1)) = (uchar)((def_temp >> 8)); } while (0)
#define int3store(T,A)  do { /*lint -save -e734 */\
                  *(((char *)(T)))   = (char) ((A));\
                  *(((char *)(T))+1) = (char) (((A) >> 8));\
                  *(((char *)(T))+2) = (char) (((A) >> 16)); \
                  /*lint -restore */} while (0)
#define int4store(T,A)  do { \
                  *(((char *)(T)))   = (char) ((A));\
                  *(((char *)(T))+1) = (char) (((A) >> 8));\
                  *(((char *)(T))+2) = (char) (((A) >> 16));\
                  *(((char *)(T))+3) = (char) (((A) >> 24)); } while (0)
#define int5store(T,A)  do { \
                  *(((char *)(T)))   = (char)((A));\
                  *(((char *)(T))+1) = (char)(((A) >> 8));\
                  *(((char *)(T))+2) = (char)(((A) >> 16));\
                  *(((char *)(T))+3) = (char)(((A) >> 24)); \
                  *(((char *)(T))+4) = (char)(((A) >> 32)); } while (0)
/* Based on int5store() from Andrey Hristov */
#define int6store(T,A)  do { \
                  *(((char *)(T)))   = (char)((A));\
                  *(((char *)(T))+1) = (char)(((A) >> 8));\
                  *(((char *)(T))+2) = (char)(((A) >> 16));\
                  *(((char *)(T))+3) = (char)(((A) >> 24)); \
                  *(((char *)(T))+4) = (char)(((A) >> 32)); \
                  *(((char *)(T))+5) = (char)(((A) >> 40)); } while (0)
#define int8store(T,A)        { uint def_temp= (uint) (A), def_temp2= (uint) ((A) >> 32); \
                  int4store((T),def_temp); \
                  int4store((T+4),def_temp2); \
                }
#ifdef WORDS_BIGENDIAN
#define float4store(T,A) do { \
                          *(((char *)(T)))   = (char) ((char *) &A)[3];\
                          *(((char *)(T))+1) = (char) ((char *) &A)[2];\
                          *(((char *)(T))+2) = (char) ((char *) &A)[1];\
                          *(((char *)(T))+3) = (char) ((char *) &A)[0]; } while (0)

#define float4get(V,M)   do { float def_temp;\
                          ((char*) &def_temp)[0] = (M)[3];\
                          ((char*) &def_temp)[1] = (M)[2];\
                          ((char*) &def_temp)[2] = (M)[1];\
                          ((char*) &def_temp)[3] = (M)[0];\
                          (V)=def_temp; } while (0)
#define float8store(T,V)  do { \
                           *(((char *)(T)))   = (char) ((char *) &(V))[7];\
                           *(((char *)(T))+1) = (char) ((char *) &(V))[6];\
                           *(((char *)(T))+2) = (char) ((char *) &(V))[5];\
                           *(((char *)(T))+3) = (char) ((char *) &(V))[4];\
                           *(((char *)(T))+4) = (char) ((char *) &(V))[3];\
                           *(((char *)(T))+5) = (char) ((char *) &(V))[2];\
                           *(((char *)(T))+6) = (char) ((char *) &(V))[1];\
                           *(((char *)(T))+7) = (char) ((char *) &(V))[0]; } while (0)

#define float8get(V,M)   do { double def_temp;\
                          ((char*) &def_temp)[0] = (M)[7];\
                          ((char*) &def_temp)[1] = (M)[6];\
                          ((char*) &def_temp)[2] = (M)[5];\
                          ((char*) &def_temp)[3] = (M)[4];\
                          ((char*) &def_temp)[4] = (M)[3];\
                          ((char*) &def_temp)[5] = (M)[2];\
                          ((char*) &def_temp)[6] = (M)[1];\
                          ((char*) &def_temp)[7] = (M)[0];\
                          (V) = def_temp; \
                         } while (0)
#else
#define float4get(V,M)   memcpy((char*) &(V),(char*) (M),sizeof(float))
#define float4store(V,M) memcpy((char*) (V),(char*) (&M),sizeof(float))

#if defined(__FLOAT_WORD_ORDER) && (__FLOAT_WORD_ORDER == __BIG_ENDIAN)
#define doublestore(T,V)  do { \
                         *(((char *)(T)))= ((char *) &(V))[4];\
                         *(((char *)(T))+1)=(char) ((char *) &(V))[5];\
                         *(((char *)(T))+2)=(char) ((char *) &(V))[6];\
                         *(((char *)(T))+3)=(char) ((char *) &(V))[7];\
                         *(((char *)(T))+4)=(char) ((char *) &(V))[0];\
                         *(((char *)(T))+5)=(char) ((char *) &(V))[1];\
                         *(((char *)(T))+6)=(char) ((char *) &(V))[2];\
                         *(((char *)(T))+7)=(char) ((char *) &(V))[3];} while (0)
#define doubleget(V,M) do { double def_temp;\
                         ((char*) &def_temp)[0]=(M)[4];\
                         ((char*) &def_temp)[1]=(M)[5];\
                         ((char*) &def_temp)[2]=(M)[6];\
                         ((char*) &def_temp)[3]=(M)[7];\
                         ((char*) &def_temp)[4]=(M)[0];\
                         ((char*) &def_temp)[5]=(M)[1];\
                         ((char*) &def_temp)[6]=(M)[2];\
                         ((char*) &def_temp)[7]=(M)[3];\
                         (V) = def_temp; } while (0)
#endif /* __FLOAT_WORD_ORDER */

#define float8get(V,M)   doubleget((V),(M))
#define float8store(V,M) doublestore((V),(M))
#endif /* WORDS_BIGENDIAN */

#endif /* sint2korr */

/* Define-funktions for reading and storing in machine format from/to
   short/long to/from some place in memory V should be a (not
   register) variable, M is a pointer to byte */

#ifdef WORDS_BIGENDIAN

#define ushortget(V,M)  { V = (uint16) (((uint16) ((uchar) (M)[1]))+\
                                        ((uint16) ((uint16) (M)[0]) << 8)); }
#define shortget(V,M)   { V = (short) (((short) ((uchar) (M)[1]))+\
                                       ((short) ((short) (M)[0]) << 8)); }
#define longget(V,M)    do { int32 def_temp;\
              ((char*) &def_temp)[0]=(M)[0];\
              ((char*) &def_temp)[1]=(M)[1];\
              ((char*) &def_temp)[2]=(M)[2];\
              ((char*) &def_temp)[3]=(M)[3];\
              (V)=def_temp; } while (0)
#define ulongget(V,M)    do { uint32 def_temp;\
              ((char*) &def_temp)[0]=(M)[0];\
              ((char*) &def_temp)[1]=(M)[1];\
              ((char*) &def_temp)[2]=(M)[2];\
              ((char*) &def_temp)[3]=(M)[3];\
              (V)=def_temp; }  while (0)
#define shortstore(T,A) do { \
              uint def_temp=(uint) (A) ;\
              *(((char *)(T))+1)=(char)(def_temp); \
              *(((char *)(T))+0)=(char)(def_temp >> 8); } while (0)
#define longstore(T,A)  do { \
              *(((char *)(T))+3)=(char)((A));\
              *(((char *)(T))+2)=(char)(((A) >> 8));\
              *(((char *)(T))+1)=(char)(((A) >> 16));\
              *(((char *)(T))+0)=(char)(((A) >> 24)); }  while (0)

#define doubleget(V,M)     memcpy((char*) &(V),(char*) (M),sizeof(double))
#define doublestore(T,V) memcpy((char*) (T),(char*) &(V),sizeof(double))
#define longlongget(V,M) memcpy((char*) &(V),(char*) (M),sizeof(ulonglong))
#define longlongstore(T,V) memcpy((char*) (T),(char*) &(V),sizeof(ulonglong))

#else

#define ushortget(V,M)  { V = uint2korr((M)); }
#define shortget(V,M)   { V = sint2korr((M)); }
#define longget(V,M)    { V = sint4korr((M)); }
#define ulongget(V,M)   { V = uint4korr((M)); }
#define shortstore(T,V)   int2store((T),(V))
#define longstore(T,V)    int4store((T),(V))
#ifndef doubleget
#define doubleget(V,M)    memcpy((char*) &(V),(char*) (M),sizeof(double))
#define doublestore(T,V)  memcpy((char*) (T),(char*) &(V),sizeof(double))
#endif /* doubleget */
#define longlongget(V,M)   memcpy((char*) &(V),(char*) (M),sizeof(ulonglong))
#define longlongstore(T,V) memcpy((char*) (T),(char*) &(V),sizeof(ulonglong))

#endif /* WORDS_BIGENDIAN */


