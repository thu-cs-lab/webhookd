use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use hex;
use log::*;
use ring::hmac;
use serde_derive::{Deserialize, Serialize};
use serde_json::{from_slice, Value};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    #[structopt(short, long)]
    config: PathBuf,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Config {
    listen_addr: Option<String>,
    project: Vec<Project>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Project {
    name: String,
    event: String,
    exec: String,
    working_directory: String,
    endpoint: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
    // gitlab
    token: Option<String>,
    // github
    secret: Option<String>,
}

enum Site {
    GitHub,
    GitLab,
}

impl Site {
    fn verify(&self, req: &HttpRequest, bytes: &web::Bytes, project: &Project) -> bool {
        use Site::*;
        let headers = req.headers();
        match self {
            GitHub => {
                if let Some(secret) = &project.secret {
                    if let Some(header) = headers.get("X-Hub-Signature") {
                        if let Ok(s) = header.to_str() {
                            if !s.starts_with("sha1=") {
                                warn!("X-Hub-Signature is invalid for {}, skipping", project.name);
                                false
                            } else if let Ok(signature) = hex::decode(&s.as_bytes()[5..]) {
                                let key = hmac::Key::new(
                                    hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                                    secret.as_bytes(),
                                );
                                if hmac::verify(&key, bytes, &signature).is_ok() {
                                    true
                                } else {
                                    warn!(
                                        "X-Hub-Signature HMAC verification failed for {}, skipping",
                                        project.name
                                    );
                                    false
                                }
                            } else {
                                warn!(
                                    "X-Hub-Signature is not valid hex string for {}, skipping",
                                    project.name
                                );
                                false
                            }
                        } else {
                            warn!("X-Hub-Signature is invalid for {}, skipping", project.name);
                            false
                        }
                    } else {
                        warn!("X-Hub-Signature not found for {}, skipping", project.name);
                        false
                    }
                } else {
                    false
                }
            }
            GitLab => {
                if let Some(token) = &project.token {
                    if let Some(header) = headers.get("X-Gitlab-Token") {
                        if let Ok(s) = header.to_str() {
                            if s == token {
                                true
                            } else {
                                warn!(
                                    "X-Gitlab-Token mismatch for project {}, skipping",
                                    project.name
                                );
                                false
                            }
                        } else {
                            warn!("X-Gitlab-Token is invalid for {}, skipping", project.name);
                            false
                        }
                    } else {
                        warn!("X-Gitlab-Token not found for {}, skipping", project.name);
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    fn get_event<'a>(&self, req: &'a HttpRequest, body: &'a Value) -> &'a str {
        use Site::*;
        match self {
            GitHub => {
                if let Some(header) = req.headers().get("X-GitHub-Event") {
                    if let Ok(s) = header.to_str() {
                        s
                    } else {
                        "unknown"
                    }
                } else {
                    "unknown"
                }
            }
            GitLab => body
                .get("object_kind")
                .and_then(|obj| obj.as_str())
                .unwrap_or("unknown"),
        }
    }
}

fn get_stdio(project: &Project, path: &Option<String>) -> Stdio {
    let mut stdio_file = None;
    if let Some(stdio_path) = path {
        match OpenOptions::new()
            .append(true)
            .create(true)
            .open(&stdio_path)
        {
            Ok(file) => stdio_file = Some(file),
            Err(err) => {
                warn!(
                    "Can't open file {} for project {}: {:?}",
                    stdio_path, project.name, err
                );
            }
        }
    }
    let stdio = if let Some(file) = stdio_file {
        Stdio::from(file)
    } else {
        Stdio::null()
    };
    stdio
}

async fn spawn_process(project: Project) {
    info!(
        "spawning {:?} in {}",
        project.exec, project.working_directory
    );

    let stdout = get_stdio(&project, &project.stdout);
    let stderr = get_stdio(&project, &project.stderr);
    let result = Command::new("/bin/sh")
        .arg("-c")
        .arg(&project.exec)
        .stdout(stdout)
        .stderr(stderr)
        .current_dir(&project.working_directory)
        .status();
    info!("Process {:?} exited with {:?}", project.exec, result);
}

async fn handler(req: HttpRequest, bytes: web::Bytes, config: web::Data<Config>) -> HttpResponse {
    let body: Value = if let Ok(body) = from_slice(&bytes) {
        body
    } else {
        warn!("Invalid body");
        return HttpResponse::Ok().body("");
    };
    debug!("Got json body: {:?}", body);
    let headers = req.headers();
    let site = if headers.get("X-Gitlab-Token").is_some() {
        Site::GitLab
    } else if headers.get("X-GitHub-Event").is_some() {
        Site::GitHub
    } else {
        return HttpResponse::Ok().body("");
    };
    let action = site.get_event(&req, &body);
    info!("Received hook: {}", action);
    let path = String::from(req.path());
    let mut triggered = 0;
    for project in &config.project {
        if project.endpoint.is_none() || project.endpoint == Some(path.clone()) {
            // found
            if !site.verify(&req, &bytes, &project) {
                continue;
            }
            if action != project.event {
                continue;
            }
            info!("Triggering project {}", project.name);
            actix::spawn(spawn_process(project.clone()));
            triggered += 1;
        }
    }
    info!("{} projects are triggered.", triggered);
    HttpResponse::Ok().body("")
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let args = Args::from_args();
    let mut file = File::open(&args.config)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let config: Config = toml::from_str(&content)?;
    info!("using config {:?}", config);
    let listen_addr = config
        .listen_addr
        .clone()
        .unwrap_or("127.0.0.1:8000".to_owned());
    HttpServer::new(move || {
        App::new()
            .data(config.clone())
            .wrap(middleware::Logger::default())
            .default_service(web::resource("").route(web::post().to(handler)))
    })
    .bind(listen_addr)?
    .run()
    .await
}
