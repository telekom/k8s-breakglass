#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

if [ -t 1 ] && [ "${NETWORK_DEBUG_MOTD:-1}" = "1" ]; then
	cat /etc/motd
fi
