#![allow(dead_code, unused_variables, clippy::all)]
//! Fire Crow Backend — Agentic Security Intelligence Platform
//! Complete Rust rewrite of the Python FastAPI backend.

pub mod config;
pub mod error;
pub mod models;
pub mod schemas;
pub mod middleware;
pub mod services;
pub mod agents;
pub mod orchestrator;
pub mod workers;
pub mod utils;
pub mod graph;
pub mod state;
pub mod api;

pub use config::Settings;
pub use error::{AppError, Result};
pub use state::AppState;
