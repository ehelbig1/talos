-- Store the Jira user's account ID for use in JQL queries (currentUser() doesn't work via OAuth).
ALTER TABLE atlassian_integrations ADD COLUMN IF NOT EXISTS account_id VARCHAR(255);
