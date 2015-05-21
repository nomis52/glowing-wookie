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
 * AvahiDiscoveryAgent.h
 * The Avahi implementation of DiscoveryAgentInterface.
 * Copyright (C) 2014 Simon Newton
 */

#ifndef SRC_AVAHIDISCOVERYAGENT_H_
#define SRC_AVAHIDISCOVERYAGENT_H_

#include <avahi-client/client.h>
#include <avahi-common/thread-watch.h>
#include <avahi-client/publish.h>
#include <avahi-client/lookup.h>

#include <ola/base/Macro.h>
#include <ola/io/Descriptor.h>
#include <ola/io/SelectServer.h>
#include <ola/thread/CallbackThread.h>
#include <ola/thread/Future.h>
#include <ola/thread/Mutex.h>
#include <ola/util/Backoff.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "src/DiscoveryAgent.h"
#include "src/AvahiOlaClient.h"

/**
 * @brief An implementation of DiscoveryAgentInterface that uses the Avahi.
 */
class AvahiDiscoveryAgent : public DiscoveryAgentInterface,
                                   ClientStateChangeListener {
 public:
  explicit AvahiDiscoveryAgent(const Options &options);
  ~AvahiDiscoveryAgent();

  bool Start();

  bool Stop();

  void WatchMasters(MasterEventCallback *cb);
  void StopWatchingMasters(MasterEventCallback *cb);

  void RegisterMaster(const MasterEntry &master);
  void DeRegisterMaster(const ola::network::IPV4SocketAddress &master_address);

  // Run from various callbacks.

  void ClientStateChanged(AvahiClientState state);

  void BrowseEvent(AvahiIfIndex interface,
                   AvahiProtocol protocol,
                   AvahiBrowserEvent event,
                   const char *name,
                   const char *type,
                   const char *domain,
                   AvahiLookupResultFlags flags);

  void MasterChanged(const class MasterResolver *resolver);

  static std::string BrowseEventToString(AvahiBrowserEvent state);

 private:
  typedef std::vector<class MasterResolver*> MasterResolverList;
  typedef std::map<ola::network::IPV4SocketAddress,
                   class MasterRegistration*> MasterRegistrationList;

  const std::string m_scope;
  std::auto_ptr<MasterEventCallback> m_master_callback;

  ola::io::SelectServer m_ss;
  std::auto_ptr<ola::thread::CallbackThread> m_thread;

  // Apart from initialization, these are all only access by the Avahi thread.
  std::auto_ptr<class AvahiOlaPoll> m_avahi_poll;
  std::auto_ptr<AvahiOlaClient> m_client;
  AvahiServiceBrowser *m_master_browser;
  MasterRegistrationList m_registrations;

  // These are shared between the threads and are protected with
  // m_masters_mu
  MasterResolverList m_masters;
  ola::thread::Mutex m_masters_mu;

  void RunThread(ola::thread::Future<void> *f);

  void StartServiceBrowser();
  void StopResolution();  // Required m_masters_mu to be held.

  void AddMaster(AvahiIfIndex interface,
                     AvahiProtocol protocol,
                     const std::string &name,
                     const std::string &type,
                     const std::string &domain);

  void RemoveMaster(AvahiIfIndex interface,
                        AvahiProtocol protocol,
                        const std::string &name,
                        const std::string &type,
                        const std::string &domain);

  void InternalRegisterService(MasterEntry master_entry);
  void InternalDeRegisterService(
      ola::network::IPV4SocketAddress master_address);

  DISALLOW_COPY_AND_ASSIGN(AvahiDiscoveryAgent);
};
#endif  // SRC_AVAHIDISCOVERYAGENT_H_
