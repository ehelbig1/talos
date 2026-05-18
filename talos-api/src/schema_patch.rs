use talos_module_executions as module_executions;

#[derive(SimpleObject, Clone)]
pub struct ModuleExecution {
    pub id: Uuid,
    pub module_id: Uuid,
    pub status: String,
    pub trigger_type: String,
    pub trigger_metadata: Option<String>,
    pub input_data: Option<String>,
    pub output_data: Option<String>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
    pub error_type: Option<String>,
    pub fuel_consumed: Option<i64>,
    pub memory_used_mb: Option<i32>,
    pub created_at: String,
}

impl From<module_executions::ModuleExecution> for ModuleExecution {
    fn from(exec: module_executions::ModuleExecution) -> Self {
        Self {
            id: exec.id,
            module_id: exec.module_id,
            status: exec.status.to_string(),
            trigger_type: exec.trigger_type.to_string(),
            trigger_metadata: exec.trigger_metadata.map(|v| v.to_string()),
            input_data: exec.input_data.map(|v| v.to_string()),
            output_data: exec.output_data.map(|v| v.to_string()),
            started_at: exec.started_at.to_rfc3339(),
            completed_at: exec.completed_at.map(|d| d.to_rfc3339()),
            duration_ms: exec.duration_ms,
            error_message: exec.error_message,
            error_type: exec.error_type,
            fuel_consumed: exec.fuel_consumed,
            memory_used_mb: exec.memory_used_mb,
            created_at: exec.created_at.to_rfc3339(),
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct ModuleExecutionLog {
    pub id: Uuid,
    pub execution_id: Uuid,
    pub level: String,
    pub message: String,
    pub metadata: Option<String>,
    pub created_at: String,
}

impl From<module_executions::ModuleExecutionLog> for ModuleExecutionLog {
    fn from(log: module_executions::ModuleExecutionLog) -> Self {
        Self {
            id: log.id,
            execution_id: log.execution_id,
            level: log.level.to_string(),
            message: log.message,
            metadata: log.metadata.map(|v| v.to_string()),
            created_at: log.created_at.to_rfc3339(),
        }
    }
}
