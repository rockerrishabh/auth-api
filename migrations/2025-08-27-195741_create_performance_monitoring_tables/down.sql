-- Drop performance monitoring tables

-- Drop triggers first
DROP TRIGGER IF EXISTS update_performance_issues_updated_at ON performance_issues;

DROP TRIGGER IF EXISTS update_render_metrics_updated_at ON render_metrics;

DROP TRIGGER IF EXISTS update_service_health_updated_at ON service_health;

-- Drop the trigger function
DROP FUNCTION IF EXISTS update_updated_at_column ();

-- Drop indexes
DROP INDEX IF EXISTS idx_performance_issues_status;

DROP INDEX IF EXISTS idx_performance_issues_severity;

DROP INDEX IF EXISTS idx_performance_issues_created_at;

DROP INDEX IF EXISTS idx_render_metrics_component;

DROP INDEX IF EXISTS idx_render_metrics_created_at;

DROP INDEX IF EXISTS idx_system_metrics_created_at;

DROP INDEX IF EXISTS idx_service_health_status;

DROP INDEX IF EXISTS idx_service_health_service;

DROP INDEX IF EXISTS idx_service_health_last_check;

-- Drop tables
DROP TABLE IF EXISTS service_health;

DROP TABLE IF EXISTS system_metrics;

DROP TABLE IF EXISTS render_metrics;

DROP TABLE IF EXISTS bundle_analyses;

DROP TABLE IF EXISTS performance_issues;