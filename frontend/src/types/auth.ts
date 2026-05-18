export interface LinkedAccount {
  id: string;
  provider: string;
  email: string;
  name?: string;
  pictureUrl?: string;
  linkedAt: string;
  lastLoginAt?: string;
}
