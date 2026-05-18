-- Secret expiry and rotation reminders
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS rotation_reminder_days INTEGER;
