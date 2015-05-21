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
 * MasterEntry.cpp
 * Information about a Master.
 * Copyright (C) 2015 Simon Newton
 */

#include "src/MasterEntry.h"

#include <stdint.h>
#include <ola/network/SocketAddress.h>
#include <ola/strings/Format.h>
#include <string>
#include <iostream>

using std::string;

MasterEntry::MasterEntry() {}

void MasterEntry::UpdateFrom(const MasterEntry &other) {
  service_name = other.service_name;
  address = other.address;
  priority = other.priority;
  scope = other.scope;
}

string MasterEntry::ToString() const {
  std::ostringstream out;
  out << "Controller: '" << service_name << "' @ " << address << ", priority "
      << static_cast<int>(priority) << ", scope " << scope;
  return out.str();
}

std::string MasterEntry::ServiceName() const {
  return service_name + "-" + ola::strings::IntToString(priority);
}
