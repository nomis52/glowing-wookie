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
 * BonjourDiscoveryAgent.h
 * The Bonjour implementation of DiscoveryAgentInterface.
 * Copyright (C) 2013 Simon Newton
 */

#ifndef SRC_BONJOURDISCOVERYAGENT_H_
#define SRC_BONJOURDISCOVERYAGENT_H_

#include <dns_sd.h>

#include <ola/base/Macro.h>
#include <ola/io/Descriptor.h>
#include <ola/io/SelectServer.h>
#include <ola/thread/CallbackThread.h>
#include <ola/thread/Future.h>
#include <ola/thread/Mutex.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "src/DiscoveryAgent.h"

/**
 * @brief An implementation of DiscoveryAgentInterface that uses the Apple
 * dns_sd.h library.
 */
class BonjourDiscoveryAgent : public DiscoveryAgentInterface {
 public:
  explicit BonjourDiscoveryAgent(const Options &options);
  ~BonjourDiscoveryAgent();

  bool Start();

  bool Stop();

  void RegisterMaster(const MasterEntry &master);

  void DeRegisterMaster(
      const ola::network::IPV4SocketAddress &master_address);


  /**
   * @brief Called by our static callback function when a new master is
   * found.
   */
  void BrowseResult(DNSServiceRef service_ref,
                    DNSServiceFlags flags,
                    uint32_t interface_index,
                    const std::string &service_name,
                    const std::string &regtype,
                    const std::string &reply_domain);

 private:
  typedef std::vector<class BonjourResolver*> MasterResolverList;
  typedef std::map<ola::network::IPV4SocketAddress,
                   class MasterRegistration*> MasterRegistrationList;

  ola::io::SelectServer m_ss;
  std::auto_ptr<MasterEventCallback> m_master_callback;
  std::auto_ptr<ola::thread::CallbackThread> m_thread;
  std::auto_ptr<class BonjourIOAdapter> m_io_adapter;

  // Masters
  DNSServiceRef m_master_service_ref;

  // These are all protected by m_mutex
  MasterResolverList m_masters;
  MasterResolverList m_orphaned_masters;

  std::string m_scope;
  bool m_watch_masters;
  bool m_changing_scope;
  // End protected by m_mutex

  ola::thread::Mutex m_mutex;

  MasterRegistrationList m_master_registrations;

  void RunThread();
  void TriggerScopeChange(ola::thread::Future<bool> *f);
  void StopResolution();

  void InternalRegisterMaster(MasterEntry master_entry);
  void InternalDeRegisterMaster(ola::network::IPV4SocketAddress master_address);
  void UpdateMaster(DNSServiceFlags flags,
                    uint32_t interface_index,
                    const std::string &service_name,
                    const std::string &regtype,
                    const std::string &reply_domain);

  void RunMasterCallbacks(MasterEvent event,
                          const MasterEntry &master_entry);
  void MasterChanged(const BonjourResolver *resolver);

  DISALLOW_COPY_AND_ASSIGN(BonjourDiscoveryAgent);
};
#endif  // SRC_BONJOURDISCOVERYAGENT_H_
