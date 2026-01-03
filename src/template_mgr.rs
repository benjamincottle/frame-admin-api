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
                log::info!("compiling templates complete");
                t
            }
            Err(e) => {
                log::error!("template parsing error(s): {}", e);
                exit(1);
            }
        };
        let urls = {
            let mut urls = BTreeMap::new();
            urls.insert("index".to_string(), "/frame_admin".to_string());
            urls.insert("login".to_string(), "/frame_admin/oauth/login".to_string());
            urls.insert(
                "logout".to_string(),
                "/frame_admin/oauth/logout".to_string()
            );
            // urls.insert("config".to_string(), "/frame_admin/config".to_string());
            // urls.insert("docs".to_string(), "/frame_admin/docs".to_string());
            // urls.insert("sync".to_string(), "/frame_admin/sync".to_string());
            urls.insert(
                "monitor".to_string(),
                "/frame_admin/monitor".to_string(),
            );
            urls.insert(
                "manage".to_string(),
                "/frame_admin/manage".to_string(),
            );
            urls.insert(
                "revoke".to_string(),
                "/frame_admin/oauth/revoke".to_string(),
            );
            urls
        };
        tera.register_function("url_for", make_url_for(urls));
        log::info!("setup template functions complete");
        Mutex::new(tera)
    };
}

impl TEMPLATES {
    pub fn full_reload(&self) {
        let mut templates = self.lock().unwrap();
        templates
            .full_reload()
            .expect("(TEMPLATES:full_reload) error reloading templates");
    }

    pub fn render(&self, template_name: &str, context: &tera::Context) -> String {
        let templates = self.lock().unwrap();
        templates
            .render(template_name, context)
            .expect("(TEMPLATES:render) error rendering template")
    }
}

fn make_url_for(urls: BTreeMap<String, String>) -> impl Function {
    Box::new(
        move |args: &HashMap<String, tera::Value>| -> tera::Result<tera::Value> {
            match args.get("name") {
                Some(val) => match tera::from_value::<String>(val.clone()) {
                    Ok(v) => {
                        // log::info!("(make_url_for) looking for name: {}", v);
                        Ok(tera::to_value(urls.get(&v).expect("assert key exists"))
                            .expect("couldn't convert value to tera::Value"))
                    }
                    Err(e) => Err(format!("(make_url_for) no match for name: {}", e).into()),
                },
                None => Err("(make_url_for) no value for name".into()),
            }
        },
    )
}
