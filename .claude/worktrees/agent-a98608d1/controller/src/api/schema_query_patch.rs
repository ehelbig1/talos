    /// Get execution history for a module
    async fn module_execution_history(
        &self,
        ctx: &Context<'_>,
        module_id: Uuid,
        limit: Option<i32>,
    ) -> Result<Vec<ModuleExecution>> {
        let execution_service = ctx.data::<Arc<crate::module_executions::ModuleExecutionService>>()?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // In a real implementation we'd probably want pagination, but for now we'll fetch up to `limit` executions
        let limit_val = limit.unwrap_or(50) as i64;
        
        let executions = execution_service
            .get_module_executions(module_id, *user_id, limit_val)
            .await
            .map_err(|e| async_graphql::Error::new(format!("Failed to fetch execution history: {}", e)))?;

        Ok(executions.into_iter().map(Into::into).collect())
    }

    /// Get logs for a specific module execution
    async fn module_execution_logs(
        &self,
        ctx: &Context<'_>,
        execution_id: Uuid,
    ) -> Result<Vec<ModuleExecutionLog>> {
        let execution_service = ctx.data::<Arc<crate::module_executions::ModuleExecutionService>>()?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        let logs = execution_service
            .get_execution_logs(execution_id, *user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("Failed to fetch execution logs: {}", e)))?;

        Ok(logs.into_iter().map(Into::into).collect())
    }
