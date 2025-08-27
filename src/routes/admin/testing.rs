use crate::{db::DbPool, error::AuthError};
use actix_web::{get, post, web, HttpResponse};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde_json::json;
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::db::models::*;

#[derive(Debug, serde::Serialize)]
pub struct TestSuiteResponse {
    pub id: String,
    pub name: String,
    pub total_tests: i32,
    pub passed_tests: i32,
    pub failed_tests: i32,
    pub running_tests: i32,
    pub duration_ms: i64,
    pub last_run: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, serde::Serialize)]
pub struct TestResultResponse {
    pub id: String,
    pub name: String,
    pub status: String,
    pub duration_ms: i64,
    pub timestamp: DateTime<Utc>,
    pub error: Option<String>,
    pub category: String,
    pub priority: String,
}

#[derive(Debug, serde::Serialize)]
pub struct PerformanceMetricsResponse {
    pub response_time_ms: i64,
    pub throughput_rps: i64,
    pub error_rate_percent: f64,
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub active_connections: i64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TestRunRequest {
    pub suite_id: String,
    pub test_type: Option<String>, // "unit", "integration", "e2e", "performance"
    pub parallel: Option<bool>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct TestExecutionResult {
    pub test_name: String,
    pub status: String,
    pub duration_ms: u64,
    pub output: String,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Get all test suites from database
#[get("/suites")]
pub async fn get_test_suites(pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    let test_suites = web::block({
        let pool = pool.clone();
        move || {
            let mut conn = pool
                .get()
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            use crate::db::schemas::test_suites::dsl::*;

            test_suites
                .order(last_run.desc())
                .load::<TestSuite>(&mut conn)
                .map_err(|e| AuthError::DatabaseError(e.to_string()))
        }
    })
    .await
    .map_err(|_| AuthError::DatabaseError("Blocking error".into()))??;

    let response_suites: Vec<TestSuiteResponse> = test_suites
        .into_iter()
        .map(|suite| TestSuiteResponse {
            id: suite.id.to_string(),
            name: suite.name,
            total_tests: suite.total_tests,
            passed_tests: suite.passed_tests,
            failed_tests: suite.failed_tests,
            running_tests: suite.running_tests,
            duration_ms: suite.duration_ms,
            last_run: suite.last_run,
            status: suite.status,
        })
        .collect();

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "test_suites": response_suites,
        "total": response_suites.len()
    })))
}

/// Get recent test results from database
#[get("/results")]
pub async fn get_test_results(pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    let test_results = web::block({
        let pool = pool.clone();
        move || {
            let mut conn = pool
                .get()
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            use crate::db::schemas::test_results::dsl::*;

            test_results
                .order(timestamp.desc())
                .limit(20)
                .load::<TestResult>(&mut conn)
                .map_err(|e| AuthError::DatabaseError(e.to_string()))
        }
    })
    .await
    .map_err(|_| AuthError::DatabaseError("Blocking error".into()))??;

    let response_results: Vec<TestResultResponse> = test_results
        .into_iter()
        .map(|result| TestResultResponse {
            id: result.id.to_string(),
            name: result.name,
            status: result.status,
            duration_ms: result.duration_ms,
            timestamp: result.timestamp,
            error: result.error,
            category: result.category,
            priority: result.priority,
        })
        .collect();

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "test_results": response_results,
        "total": response_results.len()
    })))
}

/// Get performance metrics from database
#[get("/performance")]
pub async fn get_performance_metrics(pool: web::Data<DbPool>) -> Result<HttpResponse, AuthError> {
    let metrics = web::block({
        let pool = pool.clone();
        move || {
            let mut conn = pool
                .get()
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            use crate::db::schemas::test_performance_metrics::dsl::*;

            test_performance_metrics
                .order(created_at.desc())
                .first::<TestPerformanceMetrics>(&mut conn)
                .optional()
                .map_err(|e| AuthError::DatabaseError(e.to_string()))
        }
    })
    .await
    .map_err(|_| AuthError::DatabaseError("Blocking error".into()))??;

    if let Some(metric) = metrics {
        let response_metrics = PerformanceMetricsResponse {
            response_time_ms: metric.response_time_ms,
            throughput_rps: metric.throughput_rps,
            error_rate_percent: metric
                .error_rate_percent
                .to_string()
                .parse::<f64>()
                .unwrap_or(0.0),
            cpu_usage_percent: metric
                .cpu_usage_percent
                .to_string()
                .parse::<f64>()
                .unwrap_or(0.0),
            memory_usage_percent: metric
                .memory_usage_percent
                .to_string()
                .parse::<f64>()
                .unwrap_or(0.0),
            active_connections: metric.active_connections,
        };

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "metrics": response_metrics,
            "timestamp": metric.created_at
        })))
    } else {
        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "metrics": null,
            "message": "No performance metrics available"
        })))
    }
}

/// Execute a test command and capture output
fn execute_test_command(command: &str, args: &[&str]) -> Result<TestExecutionResult, String> {
    let start_time = Instant::now();

    let output = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute test: {}", e))?;

    let duration = start_time.elapsed();
    let status = if output.status.success() {
        "passed"
    } else {
        "failed"
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let output_text = if !stdout.is_empty() {
        stdout.to_string()
    } else {
        stderr.to_string()
    };

    let error = if !output.status.success() && !stderr.is_empty() {
        Some(stderr.to_string())
    } else {
        None
    };

    Ok(TestExecutionResult {
        test_name: format!("{} {}", command, args.join(" ")),
        status: status.to_string(),
        duration_ms: duration.as_millis() as u64,
        output: output_text,
        error,
        timestamp: Utc::now(),
    })
}

/// Run a test suite with real test execution
#[post("/run")]
pub async fn run_test_suite(
    pool: web::Data<DbPool>,
    req: web::Json<TestRunRequest>,
) -> Result<HttpResponse, AuthError> {
    let start_time = Instant::now();
    let test_type = req.test_type.as_deref().unwrap_or("unit");

    // Update test suite status to running
    web::block({
        let pool = pool.clone();
        let suite_id = req.suite_id.clone();
        move || {
            let mut conn = pool
                .get()
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            use crate::db::schemas::test_suites::dsl::*;

            diesel::update(
                test_suites.filter(id.eq(suite_id.parse::<uuid::Uuid>().unwrap_or_default())),
            )
            .set((
                status.eq("running"),
                running_tests.eq(1),
                updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            Ok::<(), AuthError>(())
        }
    })
    .await
    .map_err(|_| AuthError::DatabaseError("Blocking error".into()))??;

    // Execute tests based on type
    let mut test_results = Vec::new();
    let mut passed_count = 0;
    let mut failed_count = 0;

    match test_type {
        "unit" => {
            // Run unit tests using cargo test
            let result = execute_test_command("cargo", &["test", "--lib"]);
            match result {
                Ok(exec_result) => {
                    test_results.push(exec_result.clone());
                    if exec_result.status == "passed" {
                        passed_count += 1;
                    } else {
                        failed_count += 1;
                    }
                }
                Err(e) => {
                    failed_count += 1;
                    test_results.push(TestExecutionResult {
                        test_name: "cargo test --lib".to_string(),
                        status: "failed".to_string(),
                        duration_ms: 0,
                        output: "".to_string(),
                        error: Some(e),
                        timestamp: Utc::now(),
                    });
                }
            }
        }
        "integration" => {
            // Run integration tests
            let result = execute_test_command("cargo", &["test", "--tests"]);
            match result {
                Ok(exec_result) => {
                    test_results.push(exec_result.clone());
                    if exec_result.status == "passed" {
                        passed_count += 1;
                    } else {
                        failed_count += 1;
                    }
                }
                Err(e) => {
                    failed_count += 1;
                    test_results.push(TestExecutionResult {
                        test_name: "cargo test --tests".to_string(),
                        status: "failed".to_string(),
                        duration_ms: 0,
                        output: "".to_string(),
                        error: Some(e),
                        timestamp: Utc::now(),
                    });
                }
            }
        }
        "performance" => {
            // Run performance tests (custom benchmark)
            let result = execute_test_command("cargo", &["bench"]);
            match result {
                Ok(exec_result) => {
                    test_results.push(exec_result.clone());
                    if exec_result.status == "passed" {
                        passed_count += 1;
                    } else {
                        failed_count += 1;
                    }
                }
                Err(e) => {
                    failed_count += 1;
                    test_results.push(TestExecutionResult {
                        test_name: "cargo bench".to_string(),
                        status: "failed".to_string(),
                        duration_ms: 0,
                        output: "".to_string(),
                        error: Some(e),
                        timestamp: Utc::now(),
                    });
                }
            }
        }
        _ => {
            // Default to unit tests
            let result = execute_test_command("cargo", &["test"]);
            match result {
                Ok(exec_result) => {
                    test_results.push(exec_result.clone());
                    if exec_result.status == "passed" {
                        passed_count += 1;
                    } else {
                        failed_count += 1;
                    }
                }
                Err(e) => {
                    failed_count += 1;
                    test_results.push(TestExecutionResult {
                        test_name: "cargo test".to_string(),
                        status: "failed".to_string(),
                        duration_ms: 0,
                        output: "".to_string(),
                        error: Some(e),
                        timestamp: Utc::now(),
                    });
                }
            }
        }
    }

    let total_duration = start_time.elapsed();

    // Update test suite status with results
    web::block({
        let pool = pool.clone();
        let suite_id = req.suite_id.clone();
        let passed = passed_count;
        let failed = failed_count;
        let duration = total_duration.as_millis() as i64;
        move || {
            let mut conn = pool
                .get()
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            use crate::db::schemas::test_suites::dsl::*;

            diesel::update(
                test_suites.filter(id.eq(suite_id.parse::<uuid::Uuid>().unwrap_or_default())),
            )
            .set((
                status.eq(if failed_count == 0 {
                    "completed"
                } else {
                    "failed"
                }),
                passed_tests.eq(passed),
                failed_tests.eq(failed),
                running_tests.eq(0),
                duration_ms.eq(duration),
                last_run.eq(Utc::now()),
                updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            Ok::<(), AuthError>(())
        }
    })
    .await
    .map_err(|_| AuthError::DatabaseError("Blocking error".into()))??;

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "message": format!("Test suite {} executed successfully", req.suite_id),
        "run_id": format!("run-{}", Utc::now().timestamp()),
        "status": if failed_count == 0 { "completed" } else { "failed" },
        "test_type": test_type,
        "total_tests": test_results.len(),
        "passed_tests": passed_count,
        "failed_tests": failed_count,
        "duration_ms": total_duration.as_millis(),
        "test_results": test_results,
        "timestamp": Utc::now()
    })))
}

/// Get available test types
#[get("/types")]
pub async fn get_test_types() -> Result<HttpResponse, AuthError> {
    let test_types = vec![
        json!({
            "id": "unit",
            "name": "Unit Tests",
            "description": "Run individual unit tests for components",
            "command": "cargo test --lib",
            "estimated_duration": "1-5 minutes"
        }),
        json!({
            "id": "integration",
            "name": "Integration Tests",
            "description": "Run integration tests between components",
            "command": "cargo test --tests",
            "estimated_duration": "5-15 minutes"
        }),
        json!({
            "id": "e2e",
            "name": "End-to-End Tests",
            "description": "Run full application flow tests",
            "command": "cargo test --test e2e",
            "estimated_duration": "10-30 minutes"
        }),
        json!({
            "id": "performance",
            "name": "Performance Tests",
            "description": "Run performance benchmarks",
            "command": "cargo bench",
            "estimated_duration": "5-20 minutes"
        }),
    ];

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "test_types": test_types,
        "total": test_types.len()
    })))
}
