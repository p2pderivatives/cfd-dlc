// Copyright 2019 CryptoGarage

#ifndef DLC_DLC_EXCEPTION_H_
#define DLC_DLC_EXCEPTION_H_

#include <exception>
#include <string>

#include "cfdcore/cfdcore_exception.h"

namespace cfd {
namespace dlc {

using cfd::core::CfdException;

class DlcException : public CfdException {
 public:
  DlcException();
  explicit DlcException(const std::string& message) : CfdException(message) {}
};

}  // namespace dlc
}  // namespace cfd

#endif  // DLC_DLC_EXCEPTION_H_
