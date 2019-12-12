// Copyright 2020 CryptoGarage

#ifndef CFD_DLC_INCLUDE_CFDDLC_CFDDLC_COMMON_H_
#define CFD_DLC_INCLUDE_CFDDLC_CFDDLC_COMMON_H_

#ifndef CFD_DLC_EXPORT
#if defined(_WIN32)
#ifdef CFD_DLC_BUILD
#define CFD_DLC_EXPORT __declspec(dllexport)
#elif defined(CFDDLC_SHARED)
#define CFD_DLC_EXPORT __declspec(dllimport)
#else
#define CFD_DLC_EXPORT
#endif
#elif defined(__GNUC__) && defined(CFD_DLC_BUILD)
#define CFD_DLC_EXPORT __attribute__((visibility("default")))
#else
#define CFD_DLC_EXPORT
#endif
#endif

#endif  // CFD_DLC_INCLUDE_CFDDLC_CFDDLC_COMMON_H_
