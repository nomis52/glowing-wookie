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
 * MasterEntry.h
 * Information about a Master
 * Copyright (C) 2015 Simon Newton
 */

#ifndef SRC_MASTERENTRY_H_
#define SRC_MASTERENTRY_H_

#include <stdint.h>
#include <ola/network/SocketAddress.h>
#include <ola/rdm/UID.h>
#include <string>
#include <vector>

/**
 * @brief Represents a master discovered using DNS-SD.
 *
 * The information in this struct is from the A and TXT records in DNS-SD.
 */
class MasterEntry {
 public:
  /** @brief The service name of the master */
  std::string service_name;

  /** @brief The address of the master */
  ola::network::IPV4SocketAddress address;

  /** @brief The master's priority */
  uint8_t priority;

  /** @brief The master's scope */
  std::string scope;

  MasterEntry();

  bool operator==(const MasterEntry &other) const {
    return (service_name == other.service_name &&
            address == other.address &&
            priority == other.priority &&
            scope == other.scope);
  }

  void UpdateFrom(const MasterEntry &other);

  std::string ToString() const;

  std::string ServiceName() const;

  friend std::ostream& operator<<(std::ostream &out,
                                  const MasterEntry &entry) {
    return out << entry.ToString();
  }
};


typedef std::vector<MasterEntry> MasterEntryList;

#endif  // SRC_MASTERENTRY_H_
