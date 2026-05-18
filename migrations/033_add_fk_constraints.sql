-- Clean up orphaned records first to handle existing data safely
DELETE FROM module_executions WHERE user_id NOT IN (SELECT id FROM users);
DELETE FROM workflows WHERE user_id NOT IN (SELECT id FROM users);

-- Add foreign key constraints for user_id columns

-- Add FK for module_executions -> users
ALTER TABLE module_executions
ADD CONSTRAINT fk_module_executions_user_id
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Add FK for workflows -> users
ALTER TABLE workflows
ADD CONSTRAINT fk_workflows_user_id
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
