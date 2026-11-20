//! credproxyd — credential-isolation daemon.
//!
//! Process split (decisions 6/39/40): the daemon is the vault's only client,
//! owns runtime secrets, terminates the explicit and transparent ingresses and
//! serves the control plane. It shares only sockets with `credstore` and
//! `credclient`.

pub mod audit;
pub mod bootstrap;
pub mod capture;
pub mod config;
pub mod control;
pub mod ingress;
pub mod mgmt;
pub mod placeholder;
pub mod policy;
pub mod proxy;
pub mod registry;
pub mod runtime;
pub mod store_client;
pub mod trust;

#[cfg(test)]
mod transparent_l7_tests;
