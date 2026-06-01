//! Cluster (remote) mode for the `mm` CLI (SPEC-1 FR-8/FR-29).
//!
//! When a controller is configured (`--server`/`MM_SERVER`), `mm run/ps/stop/rm`
//! drive the control-plane REST API with a bearer JWT instead of the local
//! single-host path. The request building (method/path/body + auth header per verb)
//! is factored into pure helpers so it is unit-tested without a live server.
use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, Request};
use reqwest::Method;
use serde_json::{json, Value};

use crate::commands::ps::PsArgs;
use crate::commands::rm::RmArgs;
use crate::commands::run::RunArgs;
use crate::commands::stop::StopArgs;

/// A configured connection to a control-plane controller.
pub struct RemoteClient {
    base: String,
    token: Option<String>,
    namespace: String,
    http: Client,
}

impl RemoteClient {
    pub fn new(base: String, token: Option<String>, namespace: String) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            namespace,
            http: Client::new(),
        }
    }

    /// Build (but do not send) a request: join the base URL + path, attach the JSON
    /// body, and add the bearer token. Kept separate from sending so it is testable.
    fn build(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Request> {
        let url = format!("{}/{}", self.base, path.trim_start_matches('/'));
        let mut req = self.http.request(method, url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        req.build().context("building request")
    }

    /// Send a request and return (status code, JSON body).
    fn send(&self, method: Method, path: &str, body: Option<&Value>) -> Result<(u16, Value)> {
        let req = self.build(method, path, body)?;
        let resp = self.http.execute(req).context("contacting controller")?;
        let status = resp.status().as_u16();
        let value = resp.json().unwrap_or(Value::Null);
        Ok((status, value))
    }

    /// Ensure the working namespace exists (idempotent; the creator becomes its
    /// admin), so a first `mm run` against a fresh controller just works.
    fn ensure_namespace(&self) -> Result<()> {
        let body = json!({ "name": self.namespace });
        let (status, body) = self.send(Method::POST, "v1alpha1/namespaces", Some(&body))?;
        // 201 created or 409/200 already-exists are both fine.
        if status >= 500 {
            bail!("controller error creating namespace: {status} {body}");
        }
        Ok(())
    }
}

/// Relative path to a namespace's machines collection.
fn machines_path(ns: &str) -> String {
    format!("v1alpha1/namespaces/{ns}/machines")
}

/// Relative path to a single machine.
fn machine_path(ns: &str, name: &str) -> String {
    format!("v1alpha1/namespaces/{ns}/machines/{name}")
}

/// The JSON body for creating a machine from `mm run` flags.
fn run_body(args: &RunArgs) -> Value {
    json!({
        "name": args.name.clone().unwrap_or_else(|| mm_host::default_name(&args.image)),
        "fleet": "default",
        "spec": {
            "image": args.image,
            "vcpus": args.cpus,
            "memory_mib": args.memory,
            "ssh": args.ssh,
            "running": true,
        }
    })
}

pub fn run(client: &RemoteClient, args: RunArgs) -> Result<()> {
    client.ensure_namespace()?;
    let body = run_body(&args);
    let (status, resp) =
        client.send(Method::POST, &machines_path(&client.namespace), Some(&body))?;
    if status >= 300 {
        bail!("controller returned {status}: {resp}");
    }
    let name = resp["name"]
        .as_str()
        .unwrap_or(body["name"].as_str().unwrap_or("?"));
    println!("{name}\tscheduled (namespace {})", client.namespace);
    Ok(())
}

pub fn ps(client: &RemoteClient, _args: PsArgs) -> Result<()> {
    let (status, resp) = client.send(Method::GET, &machines_path(&client.namespace), None)?;
    if status >= 300 {
        bail!("controller returned {status}: {resp}");
    }
    println!("{:<20} {:<10} {:<16} IMAGE", "NAME", "STATE", "IP");
    if let Some(machines) = resp["machines"].as_array() {
        for m in machines {
            let name = m["name"].as_str().unwrap_or("-");
            let state = m["status"]["state"].as_str().unwrap_or("-");
            let ip = m["status"]["ip"].as_str().unwrap_or("-");
            let image = m["spec"]["image"].as_str().unwrap_or("-");
            println!("{name:<20} {state:<10} {ip:<16} {image}");
        }
    }
    Ok(())
}

pub fn stop(client: &RemoteClient, args: StopArgs) -> Result<()> {
    let path = format!("{}/stop", machine_path(&client.namespace, &args.name));
    let (status, resp) = client.send(Method::POST, &path, None)?;
    if status >= 300 {
        bail!("controller returned {status}: {resp}");
    }
    println!("stopped {}", args.name);
    Ok(())
}

pub fn rm(client: &RemoteClient, args: RmArgs) -> Result<()> {
    // Stop first so the machine is terminal, then delete (the controller rejects
    // deleting a running machine unless forced).
    let stop_path = format!("{}/stop", machine_path(&client.namespace, &args.name));
    let _ = client.send(Method::POST, &stop_path, None);
    let (status, resp) = client.send(
        Method::DELETE,
        &machine_path(&client.namespace, &args.name),
        None,
    )?;
    if status >= 300 {
        bail!("controller returned {status}: {resp}");
    }
    println!("removed {}", args.name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> RemoteClient {
        RemoteClient::new(
            "https://ctrl.example:8080/".to_string(),
            Some("tok-123".to_string()),
            "team-a".to_string(),
        )
    }

    #[test]
    fn paths_are_namespaced() {
        assert_eq!(
            machines_path("team-a"),
            "v1alpha1/namespaces/team-a/machines"
        );
        assert_eq!(
            machine_path("team-a", "web"),
            "v1alpha1/namespaces/team-a/machines/web"
        );
    }

    #[test]
    fn run_body_carries_the_spec() {
        let args = RunArgs {
            image: "alpine:latest".into(),
            cpus: 4,
            memory: 1024,
            name: Some("web".into()),
            ssh: true,
            detach: false,
        };
        let body = run_body(&args);
        assert_eq!(body["name"], "web");
        assert_eq!(body["spec"]["image"], "alpine:latest");
        assert_eq!(body["spec"]["vcpus"], 4);
        assert_eq!(body["spec"]["memory_mib"], 1024);
        assert_eq!(body["spec"]["ssh"], true);
        assert_eq!(body["spec"]["running"], true);
    }

    #[test]
    fn build_joins_url_and_sets_bearer() {
        let c = client();
        let req = c
            .build(Method::GET, "v1alpha1/namespaces/team-a/machines", None)
            .unwrap();
        assert_eq!(req.method(), Method::GET);
        // base's trailing slash is trimmed; the path is appended cleanly.
        assert_eq!(
            req.url().as_str(),
            "https://ctrl.example:8080/v1alpha1/namespaces/team-a/machines"
        );
        let auth = req
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(auth, "Bearer tok-123");
    }

    #[test]
    fn build_without_token_omits_auth() {
        let c = RemoteClient::new("http://h".into(), None, "default".into());
        let req = c.build(Method::POST, "v1alpha1/namespaces", None).unwrap();
        assert!(req.headers().get(reqwest::header::AUTHORIZATION).is_none());
        assert_eq!(req.url().as_str(), "http://h/v1alpha1/namespaces");
    }
}
