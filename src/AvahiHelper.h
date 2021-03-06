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
 * AvahiHelper.h
 * Functions to help with reporting Avahi state.
 * Copyright (C) 2014 Simon Newton
 */

#ifndef TOOLS_E133_AVAHIHELPER_H_
#define TOOLS_E133_AVAHIHELPER_H_

#include <avahi-client/client.h>
#include <avahi-common/defs.h>

#include <string>

std::string ClientStateToString(AvahiClientState state);

std::string GroupStateToString(AvahiEntryGroupState state);

std::string BrowseEventToString(AvahiBrowserEvent state);

std::string ResolveEventToString(AvahiResolverEvent state);

std::string ProtoToString(AvahiProtocol protocol);
#endif  // TOOLS_E133_AVAHIHELPER_H_
