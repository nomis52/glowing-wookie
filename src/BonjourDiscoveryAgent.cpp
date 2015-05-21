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
 * BonjourDiscoveryAgent.cpp
 * The Bonjour implementation of DiscoveryAgentInterface.
 * Copyright (C) 2013 Simon Newton
 */

#define __STDC_LIMIT_MACROS  // for UINT8_MAX & friends

#include "src/BonjourDiscoveryAgent.h"

#include <dns_sd.h>
#include <stdint.h>
#include <ola/Callback.h>
#include <ola/base/Flags.h>
#include <ola/Logging.h>
#include <ola/network/NetworkUtils.h>
#include <ola/stl/STLUtils.h>
#include <ola/thread/CallbackThread.h>

#include <algorithm>
#include <map>
#include <string>
#include <utility>

#include "src/BonjourIOAdapter.h"
#include "src/BonjourRegistration.h"
#include "src/BonjourResolver.h"

using ola::network::IPV4SocketAddress;
using ola::thread::MutexLocker;
using std::auto_ptr;
using std::string;

// static callback functions
// ----------------------------------------------------------------------------
static void BrowseServiceCallback(DNSServiceRef service,
                                  DNSServiceFlags flags,
                                  uint32_t interface_index,
                                  DNSServiceErrorType error_code,
                                  const char *service_name,
                                  const char *regtype,
                                  const char *reply_domain,
                                  void *context) {
  BonjourDiscoveryAgent *agent =
      reinterpret_cast<BonjourDiscoveryAgent*>(context);

  OLA_INFO << "Browse event!";
  if (error_code != kDNSServiceErr_NoError) {
    OLA_WARN << "DNSServiceBrowse returned error " << error_code;
    return;
  }

  agent->BrowseResult(service, flags, interface_index, service_name, regtype,
                      reply_domain);
}

// BonjourDiscoveryAgent
// ----------------------------------------------------------------------------
BonjourDiscoveryAgent::BonjourDiscoveryAgent(
    const DiscoveryAgentInterface::Options &options)
    : m_master_callback(options.master_callback),
      m_io_adapter(new BonjourIOAdapter(&m_ss)),
      m_master_service_ref(NULL),
      m_scope(options.scope),
      m_changing_scope(false) {
}

BonjourDiscoveryAgent::~BonjourDiscoveryAgent() {
  Stop();
}

bool BonjourDiscoveryAgent::Start() {
  ola::thread::Future<bool> f;

  m_ss.Execute(ola::NewSingleCallback(
      this,
      &BonjourDiscoveryAgent::TriggerScopeChange, &f));

  m_thread.reset(new ola::thread::CallbackThread(ola::NewSingleCallback(
      this, &BonjourDiscoveryAgent::RunThread)));
  m_thread->Start();

  bool ok = f.Get();
  if (!ok) {
    Stop();
  }
  return ok;
}

bool BonjourDiscoveryAgent::Stop() {
  if (m_thread.get() && m_thread->IsRunning()) {
    m_ss.Terminate();
    m_thread->Join();
    m_thread.reset();
  }
  return true;
}

void BonjourDiscoveryAgent::RegisterMaster(
    const MasterEntry &master) {
  m_ss.Execute(ola::NewSingleCallback(
      this,
      &BonjourDiscoveryAgent::InternalRegisterMaster, master));
}

void BonjourDiscoveryAgent::DeRegisterMaster(
      const ola::network::IPV4SocketAddress &master_address) {
  m_ss.Execute(ola::NewSingleCallback(
      this, &BonjourDiscoveryAgent::InternalDeRegisterMaster,
      master_address));
}

void BonjourDiscoveryAgent::BrowseResult(DNSServiceRef service_ref,
                                         DNSServiceFlags flags,
                                         uint32_t interface_index,
                                         const string &service_name,
                                         const string &regtype,
                                         const string &reply_domain) {
  MutexLocker lock(&m_mutex);
  if (m_changing_scope) {
    // We're in the middle of changing scopes so don't change m_masters.
    return;
  }

  if (service_ref == m_master_service_ref) {
    UpdateMaster(flags, interface_index, service_name, regtype, reply_domain);
  } else {
    OLA_WARN << "Unknown DNSServiceRef " << service_ref;
  }
}

void BonjourDiscoveryAgent::RunThread() {
  m_ss.Run();

  ola::STLDeleteValues(&m_master_registrations);

  {
    MutexLocker lock(&m_mutex);
    StopResolution();
  }
}

void BonjourDiscoveryAgent::TriggerScopeChange(ola::thread::Future<bool> *f) {
  MutexLocker lock(&m_mutex);
  StopResolution();

  m_changing_scope = false;

  bool ret = true;

  if (m_master_callback.get()) {
    const string service_type = GenerateE133SubType(m_scope, MASTER_SERVICE);
    OLA_INFO << "Starting browse op " << service_type;
    DNSServiceErrorType error = DNSServiceBrowse(
        &m_master_service_ref,
        0,
        kDNSServiceInterfaceIndexAny,
        service_type.c_str(),
        NULL,  // domain
        &BrowseServiceCallback,
        reinterpret_cast<void*>(this));

    if (error == kDNSServiceErr_NoError) {
      m_io_adapter->AddDescriptor(m_master_service_ref);
    } else {
      OLA_WARN << "DNSServiceBrowse returned " << error;
      ret = false;
    }
  }

  if (f) {
    f->Set(ret);
  }
}

void BonjourDiscoveryAgent::StopResolution() {
  // Tear down the existing resolution
  ola::STLDeleteElements(&m_masters);
  ola::STLDeleteElements(&m_orphaned_masters);

  if (m_master_service_ref) {
    m_io_adapter->RemoveDescriptor(m_master_service_ref);
    DNSServiceRefDeallocate(m_master_service_ref);
    m_master_service_ref = NULL;
  }
}

void BonjourDiscoveryAgent::InternalRegisterMaster(MasterEntry master) {
  std::pair<MasterRegistrationList::iterator, bool> p =
      m_master_registrations.insert(
          MasterRegistrationList::value_type(master.address, NULL));

  if (p.first->second == NULL) {
    p.first->second = new MasterRegistration(m_io_adapter.get());
  }
  MasterRegistration *registration = p.first->second;
  registration->RegisterOrUpdate(master);
}

void BonjourDiscoveryAgent::InternalDeRegisterMaster(
      ola::network::IPV4SocketAddress master_address) {
  ola::STLRemoveAndDelete(&m_master_registrations, master_address);
}

void BonjourDiscoveryAgent::UpdateMaster(DNSServiceFlags flags,
                                         uint32_t interface_index,
                                         const std::string &service_name,
                                         const std::string &regtype,
                                         const std::string &reply_domain) {
  if (flags & kDNSServiceFlagsAdd) {
    BonjourResolver *master = new BonjourResolver(
        m_io_adapter.get(),
        ola::NewCallback(
            this,
            &BonjourDiscoveryAgent::MasterChanged),
        interface_index, service_name, regtype,
        reply_domain);

    DNSServiceErrorType error = master->StartResolution();
    OLA_INFO << "Starting resolution for " << *master << ", ret was "
             << error;

    if (error == kDNSServiceErr_NoError) {
      m_masters.push_back(master);
      OLA_INFO << "Added " << *master << " at " << m_masters.back();
    } else {
      OLA_WARN << "Failed to start resolution for " << *master;
      delete master;
    }
  } else {
    BonjourResolver master(m_io_adapter.get(),
                           NULL, interface_index,
                           service_name, regtype, reply_domain);
    MasterResolverList::iterator iter = m_masters.begin();
    for (; iter != m_masters.end(); ++iter) {
      if (**iter == master) {
        MasterEntry entry;
        (*iter)->GetMasterEntry(&entry);
        RunMasterCallbacks(MASTER_REMOVED, entry);

        // Cancel DNSServiceRef.
        OLA_INFO << "Removed " << master << " at " << *iter;
        delete *iter;
        m_masters.erase(iter);
        return;
      }
    }
    OLA_INFO << "Failed to find " << master;
  }
}

void BonjourDiscoveryAgent::MasterChanged(const BonjourResolver *resolver) {
  MasterEntry entry;
  resolver->GetMasterEntry(&entry);
  OLA_INFO << "Update for " << entry;

  MutexLocker lock(&m_mutex);
  m_master_callback->Run(MASTER_ADDED, entry);
}

void BonjourDiscoveryAgent::RunMasterCallbacks(
    DiscoveryAgentInterface::MasterEvent event,
    const MasterEntry &entry) {
  m_master_callback->Run(event, entry);
}

