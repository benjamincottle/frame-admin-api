use std::{
    collections::BTreeMap,
    process::exit,
    sync::{LazyLock, Mutex},
};
use tera::{Kwargs, State, Tera, TeraResult};

pub static TEMPLATES: LazyLock<Templates> = LazyLock::new(|| {
    let mut tera = Tera::new();
    // Functions must be registered before loading: Tera checks every call at parse time.
    let urls = {
        let mut urls = BTreeMap::new();
        urls.insert("index".to_string(), "/frame_admin".to_string());
        urls.insert("login".to_string(), "/frame_admin/oauth/login".to_string());
        urls.insert(
            "logout".to_string(),
            "/frame_admin/oauth/logout".to_string(),
        );
        urls.insert("monitor".to_string(), "/frame_admin/monitor".to_string());
        urls.insert("manage".to_string(), "/frame_admin/manage".to_string());
        urls.insert(
            "revoke".to_string(),
            "/frame_admin/oauth/revoke".to_string(),
        );
        urls
    };
    tera.register_function("url_for", make_url_for(urls));
    log::info!("setup template functions complete");
    match tera.load_from_glob("templates/*.html.tera") {
        Ok(()) => log::info!("compiling templates complete"),
        Err(e) => {
            log::error!("template parsing error(s): {}", e);
            exit(1);
        }
    }
    // Tera only autoescapes files ending .html/.htm/.xml by default; ours end
    // .html.tera, so opt them in explicitly.
    tera.autoescape_on([".html.tera"]);
    Templates(Mutex::new(tera))
});

pub struct Templates(Mutex<Tera>);

impl Templates {
    pub fn full_reload(&self) {
        let mut templates = self.0.lock().unwrap_or_else(|e| e.into_inner());
        templates
            .full_reload()
            .expect("(TEMPLATES:full_reload) error reloading templates");
    }

    pub fn render(&self, template_name: &str, context: &tera::Context) -> String {
        let templates = self.0.lock().unwrap_or_else(|e| e.into_inner());
        templates
            .render(template_name, context)
            .expect("(TEMPLATES:render) error rendering template")
    }
}

fn make_url_for(
    urls: BTreeMap<String, String>,
) -> impl Fn(Kwargs, &State) -> TeraResult<String> + Send + Sync + 'static {
    move |kwargs: Kwargs, _: &State| {
        let name = kwargs.must_get::<&str>("name")?;
        urls.get(name).cloned().ok_or_else(|| {
            tera::Error::message(format!("(make_url_for) no match for name: {name}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_render() {
        let mut context = tera::Context::new();
        context.insert("csp_nonce", "nonce123");
        let index = TEMPLATES.render("index.html.tera", &context);
        assert!(index.contains("nonce=\"nonce123\""));
        assert!(index.contains("href=\"/frame_admin/oauth/login\""));

        // main() reloads at startup; escaping must survive the reload.
        TEMPLATES.full_reload();
        context.insert("error", "<b>x</b>");
        let index = TEMPLATES.render("index.html.tera", &context);
        assert!(index.contains("&lt;b&gt;x&lt;/b&gt;"));

        let mut context = tera::Context::new();
        context.insert("csp_nonce", "nonce123");
        context.insert("is_authenticated", &true);
        for page in ["manage", "monitor"] {
            context.insert("current_page", page);
            let html = TEMPLATES.render(&format!("{page}.html.tera"), &context);
            assert!(html.contains("action=\"/frame_admin/oauth/logout\""));
        }
    }
}
