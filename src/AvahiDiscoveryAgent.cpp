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
 * AvahiDiscoveryAgent.cpp
 * The Avahi implementation of DiscoveryAgentInterface.
 * Copyright (C) 2013 Simon Newton
 */

#include "src/AvahiDiscoveryAgent.h"

#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/alternative.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/strlst.h>

#include <netinet/in.h>
#include <ola/Callback.h>
#include <ola/io/Descriptor.h>
#include <ola/Logging.h>
#include <ola/network/NetworkUtils.h>
#include <ola/stl/STLUtils.h>
#include <ola/thread/Future.h>
#include <stdint.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "src/AvahiHelper.h"
#include "src/AvahiOlaPoll.h"

using ola::network::IPV4Address;
using ola::network::IPV4SocketAddress;
using ola::NewCallback;
using ola::NewSingleCallback;
using ola::thread::MutexLocker;
using std::auto_ptr;
using std::ostringstream;
using std::string;

// MasterResolver
// ----------------------------------------------------------------------------
class MasterResolver {
 public:
  typedef ola::Callback1<void, const MasterResolver*> ChangeCallback;

  MasterResolver(ChangeCallback *callback,
                 AvahiOlaClient *client,
                 AvahiIfIndex interface_index,
                 AvahiProtocol protocol,
                 const std::string &service_name,
                 const std::string &type,
                 const std::string &domain);

  ~MasterResolver();

  bool operator==(const MasterResolver &other) const;

  std::string ToString() const;

  friend std::ostream& operator<<(std::ostream &out,
                                  const MasterResolver &info) {
    return out << info.ToString();
  }

  bool StartResolution();

  bool GetMasterEntry(MasterEntry *entry) const;

  void ResolveEvent(AvahiResolverEvent event,
                    const AvahiAddress *a,
                    uint16_t port,
                    AvahiStringList *txt);

 private:
  std::auto_ptr<ChangeCallback> m_callback;
  AvahiOlaClient *m_client;
  AvahiServiceResolver *m_resolver;

  const AvahiIfIndex m_interface_index;
  const AvahiProtocol m_protocol;
  const std::string m_service_name;
  const std::string m_type;
  const std::string m_domain;

  uint8_t m_priority;
  ola::network::IPV4SocketAddress m_resolved_address;
  std::string m_scope;

  bool ExtractString(AvahiStringList *txt_list,
                     const std::string &key,
                     std::string *dest);
  bool ExtractInt(AvahiStringList *txt_list,
                  const std::string &key, unsigned int *dest);
  bool CheckVersionMatches(
      AvahiStringList *txt_list,
      const string &key, unsigned int version);

  static const uint8_t DEFAULT_PRIORITY;
};

const uint8_t MasterResolver::DEFAULT_PRIORITY = 100;

// MasterRegistration
// ----------------------------------------------------------------------------
class MasterRegistration : public ClientStateChangeListener {
 public:
  explicit MasterRegistration(AvahiOlaClient *client);
  ~MasterRegistration();

  void ClientStateChanged(AvahiClientState state);

  void RegisterOrUpdate(const MasterEntry &master);

  void GroupEvent(AvahiEntryGroupState state);

 private:
  AvahiOlaClient *m_client;
  MasterEntry m_master_entry;
  AvahiEntryGroup *m_entry_group;

  void PerformRegistration();
  bool AddGroupEntry(AvahiEntryGroup *group);
  void UpdateRegistration(const MasterEntry &new_master);
  void CancelRegistration();

  AvahiStringList *BuildTxtRecord(const MasterEntry &master);

  DISALLOW_COPY_AND_ASSIGN(MasterRegistration);
};

// static callback functions
// ----------------------------------------------------------------------------

namespace {

static void browse_callback(AvahiServiceBrowser *b,
                            AvahiIfIndex interface,
                            AvahiProtocol protocol,
                            AvahiBrowserEvent event,
                            const char *name,
                            const char *type,
                            const char *domain,
                            AvahiLookupResultFlags flags,
                            void* data) {
  AvahiDiscoveryAgent *agent =
      reinterpret_cast<AvahiDiscoveryAgent*>(data);

  OLA_INFO << "Browse event!";
  agent->BrowseEvent(interface, protocol, event, name, type, domain, flags);
  (void) b;
}

static void resolve_callback(AvahiServiceResolver *r,
                             AvahiIfIndex interface,
                             AvahiProtocol protocol,
                             AvahiResolverEvent event,
                             const char *name,
                             const char *type,
                             const char *domain,
                             const char *host_name,
                             const AvahiAddress *a,
                             uint16_t port,
                             AvahiStringList *txt,
                             AvahiLookupResultFlags flags,
                             void *userdata) {
  MasterResolver *resolver =
    reinterpret_cast<MasterResolver*>(userdata);
  OLA_INFO << "Resolve event!";
  resolver->ResolveEvent(event, a, port, txt);

  (void) r;
  (void) interface;
  (void) protocol;
  (void) name;
  (void) type;
  (void) domain;
  (void) host_name;
  (void) flags;
}

static void entry_group_callback(AvahiEntryGroup *group,
                                 AvahiEntryGroupState state,
                                 void *data) {
  MasterRegistration *master_registration =
      reinterpret_cast<MasterRegistration*>(data);
  master_registration->GroupEvent(state);
  (void) group;
}
}  // namespace

// MasterResolver
// ----------------------------------------------------------------------------
MasterResolver::MasterResolver(ChangeCallback *callback,
                               AvahiOlaClient *client,
                               AvahiIfIndex interface_index,
                               AvahiProtocol protocol,
                               const std::string &service_name,
                               const std::string &type,
                               const std::string &domain)
    : m_callback(callback),
      m_client(client),
      m_resolver(NULL),
      m_interface_index(interface_index),
      m_protocol(protocol),
      m_service_name(service_name),
      m_type(type),
      m_domain(domain) {
}


MasterResolver::~MasterResolver() {
  if (m_resolver) {
    avahi_service_resolver_free(m_resolver);
    m_resolver = NULL;
  }
}

bool MasterResolver::operator==(const MasterResolver &other) const {
  return (m_interface_index == other.m_interface_index &&
          m_protocol == other.m_protocol &&
          m_service_name == other.m_service_name &&
          m_type == other.m_type &&
          m_domain == other.m_domain);
}

string MasterResolver::ToString() const {
  std::ostringstream str;
  str << m_service_name << "." << m_type << m_domain << " on iface "
      << m_interface_index;
  return str.str();
}

bool MasterResolver::StartResolution() {
  if (m_resolver) {
    return true;
  }

  m_resolver = m_client->CreateServiceResolver(
      m_interface_index, m_protocol, m_service_name, m_type, m_domain,
        AVAHI_PROTO_INET, static_cast<AvahiLookupFlags>(0), resolve_callback,
      this);
  if (!m_resolver) {
    OLA_WARN << "Failed to start resolution for " << m_service_name << "."
             << m_type << ": " << m_client->GetLastError();
    return false;
  }
  return true;
}

bool MasterResolver::GetMasterEntry(MasterEntry *entry) const {
  entry->service_name = m_service_name;
  entry->priority = m_priority;
  entry->scope = m_scope;
  entry->address = m_resolved_address;
  return true;
}

void MasterResolver::ResolveEvent(AvahiResolverEvent event,
                                  const AvahiAddress *address,
                                  uint16_t port,
                                  AvahiStringList *txt) {
  if (event == AVAHI_RESOLVER_FAILURE) {
    OLA_WARN << "Failed to resolve " << m_service_name << "." << m_type
             << ", proto: " << ProtoToString(m_protocol);
    return;
  }

  if (address->proto != AVAHI_PROTO_INET) {
    return;
  }

  if (!CheckVersionMatches(txt,
                           DiscoveryAgentInterface::TXT_VERSION_KEY,
                           DiscoveryAgentInterface::TXT_VERSION)) {
    return;
  }

  unsigned int priority;
  if (!ExtractInt(txt, DiscoveryAgentInterface::PRIORITY_KEY, &priority)) {
    return;
  }

  if (!ExtractString(txt, DiscoveryAgentInterface::SCOPE_KEY, &m_scope)) {
    return;
  }

  m_priority = static_cast<uint8_t>(priority);
  m_resolved_address = IPV4SocketAddress(
      IPV4Address(address->data.ipv4.address), port);
  if (m_callback.get()) {
    m_callback->Run(this);
  }
}

bool MasterResolver::ExtractString(AvahiStringList *txt_list,
                                           const std::string &key,
                                           std::string *dest) {
  AvahiStringList *entry = avahi_string_list_find(txt_list, key.c_str());
  if (!entry) {
    return false;
  }
  char *key_result = NULL;
  char *value = NULL;
  size_t length = 0;

  if (avahi_string_list_get_pair(entry, &key_result, &value, &length)) {
    OLA_WARN << "avahi_string_list_get_pair for " << key << " failed";
    return false;
  }

  if (key != string(key_result)) {
    OLA_WARN << "Mismatched key, " << key << " != " << string(key_result);
    avahi_free(key_result);
    avahi_free(value);
    return false;
  }

  *dest = string(value, length);
  avahi_free(key_result);
  avahi_free(value);
  return true;
}


bool MasterResolver::ExtractInt(AvahiStringList *txt_list,
                                        const std::string &key,
                                        unsigned int *dest) {
  string value;
  if (!ExtractString(txt_list, key, &value))
    return false;

  if (!ola::StringToInt(value, dest)) {
    OLA_WARN << m_service_name << " has an invalid value of " << value
             << " for " << key;
    return false;
  }
  return true;
}

bool MasterResolver::CheckVersionMatches(
    AvahiStringList *txt_list,
    const string &key, unsigned int expected_version) {
  unsigned int version;
  if (!ExtractInt(txt_list, key, &version)) {
    return false;
  }

  if (version != expected_version) {
    OLA_WARN << "Unknown version for " << key << " : " << version << " for "
             << m_service_name;
    return false;
  }
  return true;
}

// MasterRegistration
// ----------------------------------------------------------------------------
MasterRegistration::MasterRegistration(AvahiOlaClient *client)
    : m_client(client),
      m_entry_group(NULL) {
  m_client->AddStateChangeListener(this);
}

MasterRegistration::~MasterRegistration() {
  CancelRegistration();
  m_client->RemoveStateChangeListener(this);
}

void MasterRegistration::ClientStateChanged(AvahiClientState state) {
  switch (state) {
    case AVAHI_CLIENT_S_RUNNING:
      PerformRegistration();
      break;
    default:
      CancelRegistration();
  }
}

void MasterRegistration::RegisterOrUpdate(const MasterEntry &master) {
  if (m_master_entry == master) {
    // No change.
    return;
  }

  if (m_client->GetState() != AVAHI_CLIENT_S_RUNNING) {
    // Store the master info until we change to running.
    m_master_entry = master;
    return;
  }

  if (m_entry_group) {
    OLA_INFO << "Updating master registration for " << master.address;
    UpdateRegistration(master);
  } else {
    m_master_entry = master;
    PerformRegistration();
  }
}

void MasterRegistration::GroupEvent(AvahiEntryGroupState state) {
  OLA_INFO << GroupStateToString(state);
  if (state == AVAHI_ENTRY_GROUP_COLLISION) {
    OLA_INFO << "Name collision";
  }
}

void MasterRegistration::PerformRegistration() {
  AvahiEntryGroup *group = NULL;
  if (m_entry_group) {
    group = m_entry_group;
    m_entry_group = NULL;
  } else {
    group = m_client->CreateEntryGroup(entry_group_callback, this);
    if (!group) {
      OLA_WARN << "avahi_entry_group_new() failed: "
               << m_client->GetLastError();
      return;
    }
  }

  if (!AddGroupEntry(group)) {
    avahi_entry_group_free(group);
  } else {
    m_entry_group = group;
  }
}

bool MasterRegistration::AddGroupEntry(AvahiEntryGroup *group) {
  AvahiStringList *txt_str_list = BuildTxtRecord(m_master_entry);

  OLA_INFO << "Going to register: " << m_master_entry.ServiceName();
  int ret = avahi_entry_group_add_service_strlst(
      group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
      static_cast<AvahiPublishFlags>(0),
      m_master_entry.ServiceName().c_str(),
      DiscoveryAgentInterface::MASTER_SERVICE,
      NULL, NULL, m_master_entry.address.Port(), txt_str_list);

  avahi_string_list_free(txt_str_list);

  if (ret < 0) {
    if (ret == AVAHI_ERR_COLLISION) {
      OLA_INFO << "Name collision";
    } else {
      OLA_WARN << "Failed to add " << m_master_entry << " : "
               << avahi_strerror(ret);
    }
    return false;
  }

  if (!m_master_entry.scope.empty()) {
    ostringstream sub_type;
    sub_type << "_" << m_master_entry.scope << "._sub."
             << DiscoveryAgentInterface::MASTER_SERVICE;

    ret = avahi_entry_group_add_service_subtype(
        group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
        static_cast<AvahiPublishFlags>(0),
        m_master_entry.ServiceName().c_str(),
        DiscoveryAgentInterface::MASTER_SERVICE,
        NULL, sub_type.str().c_str());

    if (ret < 0) {
      OLA_WARN << "Failed to add subtype for " << m_master_entry << " : "
               << avahi_strerror(ret);
      return false;
    }
  }

  ret = avahi_entry_group_commit(group);
  if (ret < 0) {
    OLA_WARN << "Failed to commit master " << m_master_entry << " : "
             << avahi_strerror(ret);
  }
  return ret == 0;
}

void MasterRegistration::UpdateRegistration(
    const MasterEntry &new_master) {
  if (new_master == m_master_entry) {
    return;
  }

  if (new_master.scope != m_master_entry.scope) {
    // We require a full reset.
    avahi_entry_group_reset(m_entry_group);
    m_master_entry.UpdateFrom(new_master);
    PerformRegistration();
    return;
  }

  m_master_entry.UpdateFrom(new_master);

  AvahiStringList *txt_str_list = BuildTxtRecord(m_master_entry);

  OLA_INFO << "updating  " << m_entry_group << " : " <<
    m_master_entry.ServiceName();
  int ret = avahi_entry_group_update_service_txt_strlst(
      m_entry_group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
      static_cast<AvahiPublishFlags>(0),
      m_master_entry.ServiceName().c_str(),
      DiscoveryAgentInterface::MASTER_SERVICE,
      NULL, txt_str_list);

  avahi_string_list_free(txt_str_list);

  if (ret < 0) {
    OLA_WARN << "Failed to update master " << m_master_entry << ": "
             << avahi_strerror(ret);
  }
}

void MasterRegistration::CancelRegistration() {
  if (!m_entry_group) {
    return;
  }
  avahi_entry_group_free(m_entry_group);
  m_entry_group = NULL;
}

AvahiStringList *MasterRegistration::BuildTxtRecord(
    const MasterEntry &master) {
  AvahiStringList *txt_str_list = NULL;
  txt_str_list = avahi_string_list_add_printf(
      txt_str_list, "%s=%d",
      DiscoveryAgentInterface::TXT_VERSION_KEY,
      DiscoveryAgentInterface::TXT_VERSION);

  txt_str_list = avahi_string_list_add_printf(
      txt_str_list, "%s=%d",
      DiscoveryAgentInterface::PRIORITY_KEY,
      master.priority);

  txt_str_list = avahi_string_list_add_printf(
      txt_str_list, "%s=%s",
      DiscoveryAgentInterface::SCOPE_KEY,
      master.scope.c_str());

  return txt_str_list;
}

// AvahiDiscoveryAgent
// ----------------------------------------------------------------------------
AvahiDiscoveryAgent::AvahiDiscoveryAgent(const Options &options)
    : m_scope(options.scope),
      m_master_callback(options.master_callback),
      m_master_browser(NULL) {
}

AvahiDiscoveryAgent::~AvahiDiscoveryAgent() {
  Stop();
}

bool AvahiDiscoveryAgent::Start() {
  ola::thread::Future<void> f;
  m_thread.reset(new ola::thread::CallbackThread(ola::NewSingleCallback(
      this, &AvahiDiscoveryAgent::RunThread, &f)));
  m_thread->Start();
  f.Get();
  return true;
}

bool AvahiDiscoveryAgent::Stop() {
  if (m_thread.get() && m_thread->IsRunning()) {
    m_ss.Terminate();
    m_thread->Join();
    m_thread.reset();
  }
  return true;
}

void AvahiDiscoveryAgent::RegisterMaster(const MasterEntry &master) {
  m_ss.Execute(ola::NewSingleCallback(
      this,
      &AvahiDiscoveryAgent::InternalRegisterService, master));
}

void AvahiDiscoveryAgent::DeRegisterMaster(
      const ola::network::IPV4SocketAddress &master_address) {
  m_ss.Execute(ola::NewSingleCallback(
      this, &AvahiDiscoveryAgent::InternalDeRegisterService,
      master_address));
}

void AvahiDiscoveryAgent::ClientStateChanged(AvahiClientState state) {
  if (state == AVAHI_CLIENT_S_RUNNING) {
    if (m_master_callback.get()) {
      // The server has started successfully and registered its host
      // name on the network, so we can start locating the masters.
      StartServiceBrowser();
    }
    return;
  }

  MutexLocker lock(&m_masters_mu);
  StopResolution();
}

void AvahiDiscoveryAgent::RunThread(ola::thread::Future<void> *future) {
  m_avahi_poll.reset(new AvahiOlaPoll(&m_ss));
  m_client.reset(new AvahiOlaClient(m_avahi_poll.get()));
  m_client->AddStateChangeListener(this);

  m_ss.Execute(NewSingleCallback(future, &ola::thread::Future<void>::Set));
  m_ss.Execute(NewSingleCallback(m_client.get(), &AvahiOlaClient::Start));
  m_ss.Run();

  m_client->RemoveStateChangeListener(this);

  {
    MutexLocker lock(&m_masters_mu);
    StopResolution();
  }

  ola::STLDeleteValues(&m_registrations);

  m_client->Stop();
  m_client.reset();
  m_avahi_poll.reset();
}

void AvahiDiscoveryAgent::BrowseEvent(AvahiIfIndex interface,
                                          AvahiProtocol protocol,
                                          AvahiBrowserEvent event,
                                          const char *name,
                                          const char *type,
                                          const char *domain,
                                          AvahiLookupResultFlags flags) {
  switch (event) {
    case AVAHI_BROWSER_FAILURE:
      OLA_WARN << "(Browser) " << m_client->GetLastError();
      return;
    case AVAHI_BROWSER_NEW:
      if (protocol == AVAHI_PROTO_INET) {
        AddMaster(interface, protocol, name, type, domain);
      }
      break;
    case AVAHI_BROWSER_REMOVE:
      if (protocol == AVAHI_PROTO_INET) {
        RemoveMaster(interface, protocol, name, type, domain);
      }
      break;
    default:
      {}
  }
  (void) flags;
}

void AvahiDiscoveryAgent::MasterChanged(const MasterResolver *resolver) {
  MasterEntry entry;
  resolver->GetMasterEntry(&entry);
  m_master_callback->Run(MASTER_ADDED, entry);
}

void AvahiDiscoveryAgent::StartServiceBrowser() {
  ostringstream service;
  {
    MutexLocker lock(&m_masters_mu);
    service << "_" << m_scope;
  }
  service << "._sub." << MASTER_SERVICE;

  m_master_browser = m_client->CreateServiceBrowser(
      AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
      service.str().c_str(), NULL,
      static_cast<AvahiLookupFlags>(0), browse_callback, this);
  if (!m_master_browser) {
    OLA_WARN << "Failed to start browsing for " << MASTER_SERVICE
             << ": " << m_client->GetLastError();
  }
  OLA_INFO << "Started browsing for " << service.str();
}

void AvahiDiscoveryAgent::StopResolution() {
  // Tear down the existing resolution
  ola::STLDeleteElements(&m_masters);

  if (m_master_browser) {
    avahi_service_browser_free(m_master_browser);
    m_master_browser = NULL;
  }
}

void AvahiDiscoveryAgent::AddMaster(AvahiIfIndex interface,
                                    AvahiProtocol protocol,
                                    const std::string &name,
                                    const std::string &type,
                                    const std::string &domain) {
  OLA_INFO << "(Browser) NEW: service " << name << " of type " << type
           << " in domain " << domain << ", iface" << interface
           << ", proto " << protocol;

  MutexLocker lock(&m_masters_mu);

  auto_ptr<MasterResolver> master(new MasterResolver(
      NewCallback(this, &AvahiDiscoveryAgent::MasterChanged),
      m_client.get(), interface, protocol, name, type, domain));

  // We get the callback multiple times for the same instance
  MasterResolverList::iterator iter = m_masters.begin();
  for (; iter != m_masters.end(); ++iter) {
    if ((**iter) == *master) {
      return;
    }
  }
  if (master->StartResolution()) {
    MasterEntry entry;
    master->GetMasterEntry(&entry);
    m_masters.push_back(master.release());
    m_master_callback->Run(MASTER_ADDED, entry);
  }
}

void AvahiDiscoveryAgent::RemoveMaster(AvahiIfIndex interface,
                                       AvahiProtocol protocol,
                                       const std::string &name,
                                       const std::string &type,
                                       const std::string &domain) {
  MasterResolver master(NULL, m_client.get(), interface, protocol, name, type,
                        domain);

  MutexLocker lock(&m_masters_mu);
  OLA_WARN << "Removing: " << master << " from list " << m_masters.size();

  MasterResolverList::iterator iter = m_masters.begin();
  for (; iter != m_masters.end(); ++iter) {
    if (**iter == master) {
      MasterEntry entry;
      (*iter)->GetMasterEntry(&entry);
      m_master_callback->Run(MASTER_REMOVED, entry);
      delete *iter;
      m_masters.erase(iter);
      OLA_INFO << "Size is now " << m_masters.size();
      return;
    }
  }
  OLA_INFO << "Failed to find " << master;
}

void AvahiDiscoveryAgent::InternalRegisterService(MasterEntry master) {
  std::pair<MasterRegistrationList::iterator, bool> p =
      m_registrations.insert(
          MasterRegistrationList::value_type(master.address, NULL));

  if (p.first->second == NULL) {
    p.first->second = new MasterRegistration(m_client.get());
  }
  MasterRegistration *registration = p.first->second;
  registration->RegisterOrUpdate(master);
}

void AvahiDiscoveryAgent::InternalDeRegisterService(
      ola::network::IPV4SocketAddress master_address) {
  ola::STLRemoveAndDelete(&m_registrations, master_address);
}
