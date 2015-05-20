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
 * DiscoveryAgent.cpp
 * The Interface for DNS-SD Discovery of E1.33 Controllers.
 * Copyright (C) 2013 Simon Newton
 */
#include "src/DiscoveryAgent.h"

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <ola/base/Flags.h>

#ifdef HAVE_DNSSD
#include "src/BonjourDiscoveryAgent.h"
#endif

#ifdef HAVE_AVAHI
#include "src/AvahiDiscoveryAgent.h"
#endif

const char DiscoveryAgentInterface::MASTER_SERVICE[] =
    "_draft-e133-master._tcp";

const char DiscoveryAgentInterface::DEFAULT_SCOPE[] = "default";

const char DiscoveryAgentInterface::PRIORITY_KEY[] = "priority";
const char DiscoveryAgentInterface::SCOPE_KEY[] = "confScope";
const char DiscoveryAgentInterface::TXT_VERSION_KEY[] = "txtvers";

DiscoveryAgentInterface* DiscoveryAgentFactory::New(
    const DiscoveryAgentInterface::Options &options) {
#ifdef HAVE_DNSSD
  return new BonjourDiscoveryAgent(options);
#endif
#ifdef HAVE_AVAHI
  return new AvahiDiscoveryAgent(options);
#endif
  return NULL;
}
