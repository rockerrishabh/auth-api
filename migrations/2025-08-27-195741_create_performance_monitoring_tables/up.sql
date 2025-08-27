?
-- Create performance monitoring tables

-- Performance Issues table
CREATE TABLE performance_issues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    issue_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL CHECK (
        severity IN (
            'low',
            'medium',
            'high',
            'critical'
        )
    ),
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    impact TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    estimated_savings VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'open' CHECK (
        status IN (
            'open',
            'in_progress',
            'resolved',
            'closed'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Bundle Analysis table
CREATE TABLE bundle_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    total_size_bytes BIGINT NOT NULL,
    gzipped_size_bytes BIGINT NOT NULL,
    chunks INTEGER NOT NULL,
    largest_chunks JSONB NOT NULL,
    unused_dependencies JSONB NOT NULL,
    optimization_opportunities JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Render Metrics table
CREATE TABLE render_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    component_name VARCHAR(255) NOT NULL,
    render_count INTEGER NOT NULL DEFAULT 0,
    average_render_time_ms BIGINT NOT NULL DEFAULT 0,
    last_render_time_ms BIGINT NOT NULL DEFAULT 0,
    memory_usage_mb DECIMAL(10, 2) NOT NULL DEFAULT 0.0,
    optimization_score INTEGER NOT NULL DEFAULT 0 CHECK (
        optimization_score >= 0
        AND optimization_score <= 100
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- System Metrics table
CREATE TABLE system_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    cpu_usage DECIMAL(5, 2) NOT NULL CHECK (
        cpu_usage >= 0.0
        AND cpu_usage <= 100.0
    ),
    memory_usage DECIMAL(5, 2) NOT NULL CHECK (
        memory_usage >= 0.0
        AND memory_usage <= 100.0
    ),
    disk_usage DECIMAL(5, 2) NOT NULL CHECK (
        disk_usage >= 0.0
        AND disk_usage <= 100.0
    ),
    network_usage DECIMAL(5, 2) NOT NULL CHECK (
        network_usage >= 0.0
        AND network_usage <= 100.0
    ),
    response_time_ms BIGINT NOT NULL DEFAULT 0,
    uptime_seconds BIGINT NOT NULL DEFAULT 0,
    active_users INTEGER NOT NULL DEFAULT 0,
    error_rate DECIMAL(5, 2) NOT NULL DEFAULT 0.0 CHECK (
        error_rate >= 0.0
        AND error_rate <= 100.0
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Service Health table
CREATE TABLE service_health (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    service_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'healthy' CHECK (
        status IN (
            'healthy',
            'warning',
            'critical',
            'down'
        )
    ),
    response_time_ms BIGINT NOT NULL DEFAULT 0,
    last_check TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    endpoint VARCHAR(500) NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_performance_issues_status ON performance_issues (status);

CREATE INDEX idx_performance_issues_severity ON performance_issues (severity);

CREATE INDEX idx_performance_issues_created_at ON performance_issues (created_at);

CREATE INDEX idx_render_metrics_component ON render_metrics (component_name);

CREATE INDEX idx_render_metrics_created_at ON render_metrics (created_at);

CREATE INDEX idx_system_metrics_created_at ON system_metrics (created_at);

CREATE INDEX idx_service_health_status ON service_health (status);

CREATE INDEX idx_service_health_service ON service_health (service_name);

CREATE INDEX idx_service_health_last_check ON service_health (last_check);

-- Create updated_at trigger function if it doesn't exist
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER update_performance_issues_updated_at 
    BEFORE UPDATE ON performance_issues 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_render_metrics_updated_at 
    BEFORE UPDATE ON render_metrics 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_service_health_updated_at 
    BEFORE UPDATE ON service_health 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();