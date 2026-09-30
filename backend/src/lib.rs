#![allow(dead_code, unused_variables, clippy::all)]
//! Fire Crow Backend — Agentic Security Intelligence Platform
//! Complete Rust rewrite of the Python FastAPI backend.

pub mod agents;
pub mod api;
pub mod config;
pub mod error;
pub mod graph;
pub mod middleware;
pub mod models;
pub mod orchestrator;
pub mod schemas;
pub mod services;
pub mod state;
pub mod utils;
pub mod workers;

pub use config::Settings;
pub use error::{AppError, Result};
pub use state::AppState;
