// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import type { InjectionKey } from "vue";
import type AuthService from "@/services/auth";

export const AuthKey: InjectionKey<AuthService> = Symbol("auth");
