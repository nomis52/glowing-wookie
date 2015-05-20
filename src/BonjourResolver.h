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
 * BonjourResolver.h
 * Resolve service names using Bonjour.
 * Copyright (C) 2014 Simon Newton
 */

#ifndef SRC_BONJOURRESOLVER_H_
#define SRC_BONJOURRESOLVER_H_

#include <dns_sd.h>

#include <ola/Callback.h>
#include <ola/Logging.h>
#include <ola/base/Macro.h>
#include <ola/network/IPV4Address.h>
#include <ola/network/SocketAddress.h>
#include <string>

#include "src/MasterEntry.h"

class BonjourIOAdapter;

class BonjourResolver {
 public:
  typedef ola::Callback1<void, const BonjourResolver*> ChangeCallback;

  BonjourResolver(BonjourIOAdapter *io_adapter,
                  ChangeCallback *callback,
                  uint32_t interface_index,
                  const std::string &service_name,
                  const std::string &regtype,
                  const std::string &reply_domain);

  ~BonjourResolver();

  bool operator==(const BonjourResolver &other) const {
    return (interface_index == other.interface_index &&
            service_name == other.service_name &&
            regtype == other.regtype &&
            reply_domain == other.reply_domain);
  }

  std::string ToString() const {
    std::ostringstream str;
    OLA_INFO << "Service name is " << service_name;
    str << service_name << "." << regtype << reply_domain << " on iface "
        << interface_index;
    return str.str();
  }

  friend std::ostream& operator<<(std::ostream &out,
                                  const BonjourResolver &info) {
    return out << info.ToString();
  }

  DNSServiceErrorType StartResolution();

  void ResolveHandler(DNSServiceErrorType errorCode,
                      const std::string &host_target,
                      uint16_t port,
                      uint16_t txt_length,
                      const unsigned char *txt_data);

  void UpdateAddress(const ola::network::IPV4Address &v4_address);

  std::string ServiceName() const { return service_name; }
  std::string Scope() const { return m_scope; }
  uint8_t Priority() const { return m_priority; }

  ola::network::IPV4SocketAddress ResolvedAddress() const {
    return m_resolved_address;
  }

  void GetMasterEntry(MasterEntry *entry) const;

 private:
  BonjourIOAdapter *m_io_adapter;
  ChangeCallback *m_callback;
  bool m_resolve_in_progress;
  DNSServiceRef m_resolve_ref;

  bool to_addr_in_progress;
  DNSServiceRef m_to_addr_ref;

  uint32_t interface_index;
  const std::string service_name;
  const std::string regtype;
  const std::string reply_domain;
  std::string m_host_target;

  std::string m_scope;
  uint8_t m_priority;

  ola::network::IPV4SocketAddress m_resolved_address;

  bool ProcessTxtData(uint16_t txt_length,
                      const unsigned char *txt_data);

  bool ExtractString(uint16_t txt_length,
                     const unsigned char *txt_data,
                     const std::string &key,
                     std::string *dest);
  bool ExtractInt(uint16_t txt_length,
                  const unsigned char *txt_data,
                  const std::string &key, unsigned int *dest);

  bool CheckVersionMatches(
    uint16_t txt_length,
    const unsigned char *txt_data,
    const std::string &key,
    unsigned int version);

  void RunCallback();

  static const uint8_t DEFAULT_PRIORITY;

  DISALLOW_COPY_AND_ASSIGN(BonjourResolver);
};
#endif  // SRC_BONJOURRESOLVER_H_
