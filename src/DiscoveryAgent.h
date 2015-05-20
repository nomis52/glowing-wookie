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
 * DiscoveryAgent.h
 * The Interface for DNS-SD Discovery & Registration.
 * Copyright (C) 2013 Simon Newton
 */

#ifndef SRC_DISCOVERYAGENT_H_
#define SRC_DISCOVERYAGENT_H_

#include <stdint.h>
#include <ola/base/Macro.h>
#include <ola/Callback.h>
#include <ola/network/SocketAddress.h>
#include <string>
#include <vector>

#include "src/MasterEntry.h"

/**
 * @brief The interface to E1.33 DNS-SD operations like register, browse etc.
 *
 * The DiscoveryAgentInterface encapsulates the DNS-SD operations of
 * registering and browsing for masters.
 *
 * Two implementations exists: Bonjour (Apple) and Avahi.
 *
 * Since the implementation of this interface depends on which DNS-SD library
 * is available on the platform, the DiscoveryAgentFactory::New() should be
 * used to create instances of DiscoveryAgentInterface.
 */
class DiscoveryAgentInterface {
 public:
  struct Options {
    Options() {}

    std::string scope;
    bool watch_masters;
  };

  enum MasterEvent {
    MASTER_ADDED,
    MASTER_REMOVED,
  };

  typedef ola::Callback2<void, MasterEvent, const MasterEntry&>
      MasterEventCallback;

  virtual ~DiscoveryAgentInterface() {}

  /**
   * @brief Start the DiscoveryAgent.
   *
   * In both the Avahi and Bonjour implementations this starts the DNS-SD
   * thread.
   */
  virtual bool Start() = 0;

  /**
   * @brief Stop the DiscoveryAgent.
   *
   * Once this returns any threads will have been terminated.
   */
  virtual bool Stop() = 0;

  /**
   * @brief Change the scope for discovery.
   *
   * The scope corresponds to the sub_type in DNS-SD. If the scope is the empty
   * string, all controllers will be discovered.
   *
   * Once this method returns, FindControllers() will only return controllers
   * in the current scope.
   */
  virtual void SetScope(const std::string &scope) = 0;

  /**
   * @brief Watch for masters.
   */
  virtual void WatchMasters(MasterEventCallback *cb) = 0;

  /**
   * @brief Watch for masters.
   */
  virtual void StopWatchingMasters(MasterEventCallback *cb) = 0;

  /**
   * @brief Register the SocketAddress as a master.
   * @param master The master entry to register in DNS-SD.
   *
   * If this is called twice with a controller with the same IPV4SocketAddress
   * the TXT field will be updated with the newer values.
   *
   * Registration may be performed in a separate thread.
   */
  virtual void RegisterMaster(const MasterEntry &master) = 0;

  /**
   * @brief De-Register the SocketAddress as a Master.
   * @param master_address The SocketAddress to de-register. This should be
   * the same as what was in the MasterEntry that was passed to
   * RegisterMaster().
   *
   * DeRegistration may be performed in a separate thread.
   */
  virtual void DeRegisterMaster(
      const ola::network::IPV4SocketAddress &master_address) = 0;

  static const char MASTER_SERVICE[];
  static const char DEFAULT_SCOPE[];

  static const char PRIORITY_KEY[];
  static const char SCOPE_KEY[];
  static const char TXT_VERSION_KEY[];

  static const uint8_t TXT_VERSION = 1;
};

/**
 * @brief A Factory which produces implementations of DiscoveryAgentInterface.
 * The exact type of object returns depends on what implementation of DNS-SD was
 * available at build time.
 */
class DiscoveryAgentFactory {
 public:
  DiscoveryAgentFactory() {}

  /**
   * @brief Create a new DiscoveryAgent.
   * This returns a DiscoveryAgent appropriate for the platform. It can
   * either be a BonjourDiscoveryAgent or a AvahiDiscoveryAgent.
   */
  DiscoveryAgentInterface* New(
      const DiscoveryAgentInterface::Options &options);

 private:
  DISALLOW_COPY_AND_ASSIGN(DiscoveryAgentFactory);
};
#endif  // SRC_DISCOVERYAGENT_H_
