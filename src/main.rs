use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use log::*;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
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
    endpoint: Option<String>,
    token: Option<String>,
    event: String,
    exec: String,
    working_directory: String,
    stdout: Option<String>,
    stderr: Option<String>,
}

async fn spawn_process(project: Project) {
    info!(
        "spawning {:?} in {}",
        project.exec, project.working_directory
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(&project.exec)
        .current_dir(&project.working_directory)
        .output();
    match output {
        Ok(result) => {
            info!("Process {:?} exited with {:?}", project.exec, result.status);
            if let Some(stdout_path) = project.stdout {
                match OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&stdout_path)
                {
                    Ok(mut stdout_file) => match stdout_file.write_all(&result.stdout) {
                        Ok(()) => info!("Stdout of process {:?} logged", project.exec),
                        Err(err) => warn!(
                            "Can't write stdout for project {:?}: {:?}",
                            project.name, err
                        ),
                    },
                    Err(err) => {
                        warn!(
                            "Can't open file {} for project {}: {:?}",
                            stdout_path, project.name, err
                        );
                    }
                }
            }
            if let Some(stderr_path) = project.stderr {
                match OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&stderr_path)
                {
                    Ok(mut stderr_file) => match stderr_file.write_all(&result.stderr) {
                        Ok(()) => info!("Stderr of process {:?} logged", project.exec),
                        Err(err) => warn!(
                            "Can't write stderr for project {:?}: {:?}",
                            project.name, err
                        ),
                    },
                    Err(err) => {
                        warn!(
                            "Can't open file {} for project {}: {:?}",
                            stderr_path, project.name, err
                        );
                    }
                }
            }
        }
        Err(err) => {
            warn!("Process {:?} failed to spawn with {:?}", project.exec, err);
        }
    }
}

async fn handler(
    req: HttpRequest,
    body: web::Json<Value>,
    config: web::Data<Config>,
) -> HttpResponse {
    debug!("Got json body: {:?}", body);
    let action = body
        .get("object_kind")
        .and_then(|obj| obj.as_str())
        .unwrap_or("unknown");
    info!("Received hook: {}", action);
    let path = String::from(req.path());
    let headers = req.headers();
    let mut triggered = 0;
    for project in &config.project {
        if project.endpoint.is_none() || project.endpoint == Some(path.clone()) {
            // found
            if let Some(token) = &project.token {
                if let Some(header) = headers.get("X-Gitlab-Token") {
                    if let Ok(s) = header.to_str() {
                        if s != token {
                            warn!(
                                "X-Gitlab-Token mismatch for project {}, skipping",
                                project.name
                            );
                            continue;
                        }
                    } else {
                        warn!("X-Gitlab-Token is bad for {}, skipping", project.name);
                        continue;
                    }
                } else {
                    warn!("X-Gitlab-Token not found for {}, skipping", project.name);
                    continue;
                }
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
