-- A session records whether a second factor was VERIFIED, not only whether
-- one is still pending.
--
-- `user_sessions.is_2fa_verified` is written as `NOT totp_enabled` at a
-- password or OAuth login, so for an account with no second factor enrolled it
-- is TRUE — "nothing is pending", not "a factor was proven". Every
-- `require_2fa` gate read that flag, so on such an account the operations the
-- security documentation calls 2FA-protected (master-key and DEK rotation, the
-- re-encryption sweeps, API-key creation, capability grants) ran on a password
-- alone. And because enrolment revoked nothing, a refresh token minted before
-- enrolment kept renewing tokens that read as verified.
--
-- This column is set only when a TOTP or backup code was verified for the
-- session (a 2FA login, or the session that enrolled). The privileged gate
-- (`require_second_factor`) requires it. DEFAULT false: every existing session
-- reads as unverified, so the change fails closed and nobody gains a privilege
-- by migrating.
ALTER TABLE user_sessions
    ADD COLUMN IF NOT EXISTS second_factor_verified boolean NOT NULL DEFAULT false;
