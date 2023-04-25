use lazy_static::lazy_static;
use rand::{distributions::Alphanumeric, Rng};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime},
};
use tiny_http::Request;

lazy_static! {
    pub static ref SESSION_MGR: Mutex<SessionManager> = {
        let session_mgr = SessionManager {
            sessions: HashMap::new(),
            session_duration: Duration::new(3600, 0),
        };
        log::info!("[Info] (session_mgr) session manager created");
        Mutex::new(session_mgr)
    };
}

impl SESSION_MGR {
    #[allow(unused_must_use)]
    pub fn initialise(&self) {
        self.lock().unwrap();
    }
    pub fn create_session(&self) -> SessionID {
        self.clean_expired();
        let mut session_mgr = self.lock().unwrap();
        let session_id = self.generate_state();
        let session = Session::new(session_mgr.session_duration);
        session_mgr.sessions.insert(session_id.clone(), session);
        session_id
    }

    pub fn get_session_id(&self, request: &Request) -> Result<SessionID, SessionError> {
        let mut session_mgr = self.lock().unwrap();
        let cookie = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("Cookie"))
            .ok_or(SessionError::MissingCookie)?
            .value
            .to_string();
        let session_id = cookie
            .split(';')
            .find(|cookie| cookie.starts_with("session="))
            .ok_or(SessionError::InvalidCookie)?
            .trim_start_matches("session=");
        if let Some(session) = session_mgr.sessions.get(session_id) {
            if session.expires > SystemTime::now() {
                Ok(session_id.to_string())
            } else {
                session_mgr.sessions.remove(session_id);
                Err(SessionError::ExpiredSession)
            }
        } else {
            return Err(SessionError::InvalidSession);
        }
    }

    pub fn set_session_data(&self, session_id: &str, key: &str, value: &str) {
        let mut session_mgr = self.lock().unwrap();
        if let Some(session) = session_mgr.sessions.get_mut(session_id) {
            session.insert_data(key.to_string(), value.to_string());
        }
    }

    pub fn get_session_data(&self, session_id: &str, key: &str) -> Option<Value> {
        let session_mgr = self.lock().unwrap();
        if let Some(session) = session_mgr.sessions.get(session_id) {
            session.get_data(key).cloned()
        } else {
            None
        }
    }

    pub fn remove_session(&self, session_id: &str) -> bool {
        let mut session_mgr = self.lock().unwrap();
        session_mgr.sessions.remove(session_id).is_some()
    }

    fn clean_expired(&self) {
        let mut session_mgr = self.lock().unwrap();
        let now = SystemTime::now();
        session_mgr
            .sessions
            .retain(|_, session| session.expires > now);
    }

    pub fn generate_state(&self) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .map(char::from)
            .filter(|&c| {
                ('a'..='z').contains(&c) || ('A'..='Z').contains(&c) || ('0'..='9').contains(&c)
            })
            .take(64)
            .collect::<String>()
    }

    #[allow(dead_code)]
    pub fn dump(&self) {
        let session_mgr = self.lock().unwrap();
        println!("[Debug] Session Manager:");
        for (session_id, session) in session_mgr.sessions.clone() {
            println!(
                "[Debug]  session_id: {}, expires {:?}",
                session_id, session.expires
            );
            for (key, value) in session.data {
                println!("[Debug]    key: {}, value: {}", key, value);
            }
        }
    }
}

#[derive(Debug)]
pub enum SessionError {
    MissingCookie,
    InvalidCookie,
    InvalidSession,
    ExpiredSession,
}

type Key = String;
type Value = String;
pub type SessionID = String;

#[derive(Clone)]
struct Session {
    data: HashMap<Key, Value>,
    expires: SystemTime,
}

impl Session {
    fn new(session_duration: Duration) -> Self {
        Self {
            data: HashMap::new(),
            expires: SystemTime::now() + session_duration,
        }
    }

    fn insert_data(&mut self, key: Key, value: Value) {
        self.data.insert(key, value);
    }

    fn get_data(&self, key: &str) -> Option<&Value> {
        self.data.get(key)
    }
}

pub struct SessionManager {
    sessions: HashMap<SessionID, Session>,
    session_duration: Duration,
}
