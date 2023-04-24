use lazy_static::lazy_static;
use std::{
    collections::{BTreeMap, HashMap},
    process::exit,
    sync::Mutex,
};
use tera::{Function, Tera};

lazy_static! {
    pub static ref TEMPLATES: Mutex<Tera> = {
        let mut tera = match Tera::new("templates/*.html.tera") {
            Ok(t) => {
                log::info!("[Info] (template_mgr) compiling templates complete");
                t
            }
            Err(e) => {
                log::error!("[Error] (template_mgr) template parsing error(s): {}", e);
                exit(1);
            }
        };
        let urls = {
            let mut urls = BTreeMap::new();
            urls.insert("index".to_string(), "/frame_admin".to_string());
            urls.insert("login".to_string(), "/frame_admin/auth/login".to_string());
            urls.insert("logout".to_string(), "/frame_admin/auth/logout".to_string());
            urls.insert("sync".to_string(), "/frame_admin/sync".to_string());
            urls.insert(
                "telemetry".to_string(),
                "/frame_admin/telemetry".to_string(),
            );
            urls.insert("revoke".to_string(), "/frame_admin/revoke".to_string());
            urls
        };
        tera.register_function("url_for", make_url_for(urls.clone()));
        log::info!("[Info] (template_mgr) setup template functions complete");
        Mutex::new(tera)
    };
}

impl TEMPLATES {
    pub fn full_reload(&self) {
        let mut templates = self.lock().unwrap();
        templates
            .full_reload()
            .expect("[Error] (TEMPLATES:full_reload) error reloading templates");
    }

    pub fn render(&self, template_name: &str, context: &tera::Context) -> String {
        let templates = self.lock().unwrap();
        templates
            .render(template_name, context)
            .expect("[Error] (TEMPLATES:render) error rendering template")
    }
}

fn make_url_for(urls: BTreeMap<String, String>) -> impl Function {
    Box::new(
        move |args: &HashMap<String, tera::Value>| -> tera::Result<tera::Value> {
            match args.get("name") {
                Some(val) => match tera::from_value::<String>(val.clone()) {
                    Ok(v) => Ok(tera::to_value(urls.get(&v).unwrap()).unwrap()),
                    Err(e) => {
                        Err(format!("[Error] (make_url_for) no match for name: {}", e).into())
                    }
                },
                None => Err("[Error] (make_url_for) no value for name".into()),
            }
        },
    )
}
