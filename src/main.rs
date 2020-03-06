use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use log::*;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
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
    endpoint: Option<String>,
    token: Option<String>,
    event: String,
    exec: String,
    working_directory: String,
}

async fn spawn_process(project: Project) {
    info!("spawning {:?} in {}", project.exec, project.working_directory);
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(&project.exec)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(&project.working_directory)
        .status();
    info!("process {:?} exited with {:?}", project.exec, status);
}

async fn handler(
    req: HttpRequest,
    body: web::Json<Value>,
    config: web::Data<Config>,
) -> HttpResponse {
    debug!("got json body: {:?}", body);
    let path = String::from(req.path());
    let headers = req.headers();
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
            info!("Triggering project {}", project.name);
            actix::spawn(spawn_process(project.clone()));
        }
    }
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
