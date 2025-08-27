-- Create testing tables

-- Test Suites table
CREATE TABLE test_suites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    name VARCHAR(255) NOT NULL,
    total_tests INTEGER NOT NULL DEFAULT 0,
    passed_tests INTEGER NOT NULL DEFAULT 0,
    failed_tests INTEGER NOT NULL DEFAULT 0,
    running_tests INTEGER NOT NULL DEFAULT 0,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    last_run TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL DEFAULT 'idle' CHECK (
        status IN (
            'idle',
            'running',
            'completed',
            'failed',
            'paused'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Test Results table
CREATE TABLE test_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    test_suite_id UUID NOT NULL REFERENCES test_suites (id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (
        status IN (
            'passed',
            'failed',
            'skipped',
            'running',
            'pending'
        )
    ),
    duration_ms BIGINT NOT NULL DEFAULT 0,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    error TEXT,
    category VARCHAR(100) NOT NULL CHECK (
        category IN (
            'unit',
            'integration',
            'e2e',
            'performance',
            'security',
            'accessibility'
        )
    ),
    priority VARCHAR(50) NOT NULL CHECK (
        priority IN (
            'low',
            'medium',
            'high',
            'critical'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Test Performance Metrics table
CREATE TABLE test_performance_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    response_time_ms BIGINT NOT NULL DEFAULT 0,
    throughput_rps BIGINT NOT NULL DEFAULT 0,
    error_rate_percent DECIMAL(5, 2) NOT NULL DEFAULT 0.0 CHECK (
        error_rate_percent >= 0.0
        AND error_rate_percent <= 100.0
    ),
    cpu_usage_percent DECIMAL(5, 2) NOT NULL DEFAULT 0.0 CHECK (
        cpu_usage_percent >= 0.0
        AND cpu_usage_percent <= 100.0
    ),
    memory_usage_percent DECIMAL(5, 2) NOT NULL DEFAULT 0.0 CHECK (
        memory_usage_percent >= 0.0
        AND memory_usage_percent <= 100.0
    ),
    active_connections BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_test_suites_status ON test_suites (status);

CREATE INDEX idx_test_suites_last_run ON test_suites (last_run);

CREATE INDEX idx_test_results_test_suite_id ON test_results (test_suite_id);

CREATE INDEX idx_test_results_status ON test_results (status);

CREATE INDEX idx_test_results_timestamp ON test_results (timestamp);

CREATE INDEX idx_test_results_category ON test_results (category);

CREATE INDEX idx_test_performance_metrics_created_at ON test_performance_metrics (created_at);

-- Insert some sample data
INSERT INTO
    test_suites (
        name,
        total_tests,
        passed_tests,
        failed_tests,
        running_tests,
        duration_ms,
        last_run,
        status
    )
VALUES (
        'Authentication Tests',
        45,
        42,
        2,
        1,
        12000,
        NOW(),
        'running'
    ),
    (
        'API Integration Tests',
        78,
        75,
        3,
        0,
        25000,
        NOW() - INTERVAL '5 minutes',
        'completed'
    ),
    (
        'UI Component Tests',
        156,
        154,
        2,
        0,
        18000,
        NOW() - INTERVAL '10 minutes',
        'completed'
    ),
    (
        'End-to-End Tests',
        23,
        20,
        3,
        0,
        45000,
        NOW() - INTERVAL '15 minutes',
        'failed'
    );

INSERT INTO
    test_results (
        test_suite_id,
        name,
        status,
        duration_ms,
        timestamp,
        error,
        category,
        priority
    )
VALUES (
        (
            SELECT id
            FROM test_suites
            WHERE
                name = 'Authentication Tests'
            LIMIT 1
        ),
        'User Login Validation',
        'passed',
        150,
        NOW(),
        NULL,
        'unit',
        'high'
    ),
    (
        (
            SELECT id
            FROM test_suites
            WHERE
                name = 'Authentication Tests'
            LIMIT 1
        ),
        'Password Reset Flow',
        'failed',
        200,
        NOW(),
        'Timeout waiting for email service',
        'integration',
        'critical'
    ),
    (
        (
            SELECT id
            FROM test_suites
            WHERE
                name = 'API Integration Tests'
            LIMIT 1
        ),
        'Profile Update API',
        'passed',
        180,
        NOW() - INTERVAL '1 minute',
        NULL,
        'integration',
        'medium'
    ),
    (
        (
            SELECT id
            FROM test_suites
            WHERE
                name = 'UI Component Tests'
            LIMIT 1
        ),
        'Dashboard Rendering',
        'passed',
        89,
        NOW() - INTERVAL '1 minute',
        NULL,
        'unit',
        'low'
    );

INSERT INTO
    test_performance_metrics (
        response_time_ms,
        throughput_rps,
        error_rate_percent,
        cpu_usage_percent,
        memory_usage_percent,
        active_connections
    )
VALUES (
        300,
        800,
        1.5,
        60.0,
        70.0,
        800
    ),
    (
        150,
        400,
        0.8,
        30.0,
        45.0,
        400
    );