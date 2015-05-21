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
 * BonjourRegistration.cpp
 * Handles DNS-SD registration.
 * Copyright (C) 2014 Simon Newton
 */

#include "src/BonjourRegistration.h"

#include <dns_sd.h>
#include <stdint.h>
#include <ola/Logging.h>
#include <ola/network/NetworkUtils.h>
#include <ola/strings/Format.h>

#include <string>
#include <vector>

#include "src/BonjourIOAdapter.h"

using ola::network::HostToNetwork;
using ola::network::IPV4SocketAddress;
using std::auto_ptr;
using std::string;
using std::vector;
using std::ostringstream;

string GenerateE133SubType(const string &scope,
                           const string &service) {
  string service_type(service);
  if (!scope.empty()) {
    service_type.append(",_");
    service_type.append(scope);
  }
  return service_type;
}

// static callback functions
// ----------------------------------------------------------------------------
static void RegisterCallback(OLA_UNUSED DNSServiceRef service,
                             OLA_UNUSED DNSServiceFlags flags,
                             DNSServiceErrorType error_code,
                             const char *name,
                             const char *type,
                             const char *domain,
                             OLA_UNUSED void *context) {
  MasterRegistration *master_registration =
      reinterpret_cast<MasterRegistration*>(context);
  master_registration->RegisterEvent(error_code, name, type, domain);
}

// MasterRegistration
// ----------------------------------------------------------------------------

BonjourRegistration::~BonjourRegistration() {
  CancelRegistration();
}

bool BonjourRegistration::RegisterOrUpdateInternal(
    const string &service_type,
    const string &scope,
    const string &service_name,
    const IPV4SocketAddress &address,
    const string &txt_data) {
  if (m_registration_ref) {
    // This is an update.
    if (m_last_txt_data == txt_data) {
      return true;
    }

    OLA_INFO << "Updating master registration for " << address;
    // If the scope isn't changing, this is just an update.
    if (scope == m_scope) {
      return UpdateRecord(txt_data);
    }

    // Otherwise we need to cancel this registration and continue with the new
    // one.
    CancelRegistration();
  }

  const string sub_service_type = GenerateE133SubType(scope, service_type);

  OLA_INFO << "Adding " << service_name << " : '"
           << sub_service_type << "' :" << address.Port();
  DNSServiceErrorType error = DNSServiceRegister(
      &m_registration_ref,
      kDNSServiceFlagsNoAutoRename,
      0,
      service_name.c_str(),
      sub_service_type.c_str(),
      NULL,  // default domain
      NULL,  // use default host name
      HostToNetwork(address.Port()),
      txt_data.size(), txt_data.c_str(),
      &RegisterCallback,  // call back function
      this);

  if (error != kDNSServiceErr_NoError) {
    OLA_WARN << "DNSServiceRegister returned " << error;
    return false;
  }

  m_last_txt_data = txt_data;
  m_scope = scope;
  m_io_adapter->AddDescriptor(m_registration_ref);
  return true;
}

void BonjourRegistration::RegisterEvent(
    DNSServiceErrorType error_code, const std::string &name,
    const std::string &type, const std::string &domain) {
  switch (error_code) {
    case kDNSServiceErr_NameConflict:
      OLA_INFO << "Name conflict";
      CancelRegistration();
      break;
    case kDNSServiceErr_NoError:
      OLA_INFO << "Registered: " << name << "." << type << domain;
      break;
    default:
      OLA_WARN << "DNSServiceRegister for " << name << "." << type << domain
               << " returned error " << error_code;
      CancelRegistration();
  }
}

void BonjourRegistration::CancelRegistration() {
  if (m_registration_ref) {
    m_io_adapter->RemoveDescriptor(m_registration_ref);
    DNSServiceRefDeallocate(m_registration_ref);
    m_registration_ref = NULL;
  }
}

bool BonjourRegistration::UpdateRecord(const string &txt_data) {
  // Update required
  DNSServiceErrorType error = DNSServiceUpdateRecord(
      m_registration_ref, NULL,
      0, txt_data.size(), txt_data.c_str(), 0);
  if (error != kDNSServiceErr_NoError) {
    OLA_WARN << "DNSServiceUpdateRecord returned " << error;
    return false;
  }
  m_last_txt_data = txt_data;
  return true;
}

string BonjourRegistration::BuildTxtString(const vector<string> &records) {
  string txt_data;
  vector<string>::const_iterator iter = records.begin();
  for (; iter != records.end(); ++iter) {
    txt_data.append(1, static_cast<char>(iter->size()));
    txt_data.append(*iter);
  }
  return txt_data;
}

bool MasterRegistration::RegisterOrUpdate(const MasterEntry &master) {
  OLA_INFO << "Master name is " << service_name;
  return RegisterOrUpdateInternal(
      DiscoveryAgentInterface::MASTER_SERVICE,
      master.scope,
      master.ServiceName(),
      master.address,
      BuildTxtRecord(master));
}

string MasterRegistration::BuildTxtRecord(const MasterEntry &master) {
  ostringstream str;
  vector<string> records;

  str << DiscoveryAgentInterface::TXT_VERSION_KEY << "="
      << static_cast<int>(DiscoveryAgentInterface::TXT_VERSION);
  records.push_back(str.str());
  str.str("");

  str << DiscoveryAgentInterface::PRIORITY_KEY << "="
      << static_cast<int>(master.priority);
  records.push_back(str.str());
  str.str("");

  str << DiscoveryAgentInterface::SCOPE_KEY << "="
      << master.scope;
  records.push_back(str.str());
  str.str("");

  return BuildTxtString(records);
}
