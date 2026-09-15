export interface CurrentUserIdentity {
  profile?: {
    email?: string;
    preferred_username?: string;
  };
  email?: string;
  preferred_username?: string;
}

export function currentUserIdentifier(user: CurrentUserIdentity | null | undefined): string {
  return user?.profile?.email || user?.profile?.preferred_username || user?.email || user?.preferred_username || "";
}
