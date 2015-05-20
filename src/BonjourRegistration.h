/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * BonjourRegistration.h
 * Handles DNS-SD registration.
 * Copyright (C) 2014 Simon Newton
 */

#ifndef SRC_BONJOURREGISTRATION_H_
#define SRC_BONJOURREGISTRATION_H_

#include <dns_sd.h>
#include <ola/base/Macro.h>
#include <ola/network/SocketAddress.h>
#include <string>
#include <vector>

#include "src/MasterEntry.h"

class BonjourIOAdapter;

std::string GenerateE133SubType(const std::string &scope,
                                const std::string &service);

class BonjourRegistration {
 public:
  explicit BonjourRegistration(class BonjourIOAdapter *io_adapter)
      : m_io_adapter(io_adapter),
        m_registration_ref(NULL) {
  }
  virtual ~BonjourRegistration();

  void RegisterEvent(DNSServiceErrorType error_code,
                     const std::string &name,
                     const std::string &type,
                     const std::string &domain);

 protected:
  bool RegisterOrUpdateInternal(const std::string &service_type,
                                const std::string &scope,
                                const std::string &service_name,
                                const ola::network::IPV4SocketAddress &address,
                                const std::string &txt_record);

  std::string BuildTxtString(const std::vector<std::string> &records);

 private:
  class BonjourIOAdapter *m_io_adapter;
  std::string m_scope;
  std::string m_last_txt_data;
  DNSServiceRef m_registration_ref;

  void CancelRegistration();
  bool UpdateRecord(const std::string &txt_data);

  DISALLOW_COPY_AND_ASSIGN(BonjourRegistration);
};

class MasterRegistration : public BonjourRegistration {
 public:
  explicit MasterRegistration(class BonjourIOAdapter *io_adapter)
      : BonjourRegistration(io_adapter) {
  }
  ~MasterRegistration() {}

  bool RegisterOrUpdate(const MasterEntry &master);

 private:
  std::string BuildTxtRecord(const MasterEntry &master);

  DISALLOW_COPY_AND_ASSIGN(MasterRegistration);
};


#endif  // SRC_BONJOURREGISTRATION_H_
