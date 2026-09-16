use postgres::{Client, NoTls};
use std::{
    collections::VecDeque,
    ops::{Deref, DerefMut},
    sync::{LazyLock, Mutex, MutexGuard},
};

pub static CONNECTION_POOL: LazyLock<ConnectionPool> = LazyLock::new(|| {
    log::info!("empty pool created");
    ConnectionPool(Mutex::new(Pool {
        connections: VecDeque::new(),
        database_url: String::new(),
        max_size: 0,
    }))
});

pub struct ConnectionPool(Mutex<Pool>);

impl Deref for ConnectionPool {
    type Target = Mutex<Pool>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Pool {
    connections: VecDeque<Client>,
    database_url: String,
    max_size: usize,
}

/// Recover the guard even if another thread panicked while holding the lock.
/// A poisoned mutex must not be allowed to turn a single panic into a
/// server-wide, permanent outage.
fn lock_pool(pool: &Mutex<Pool>) -> MutexGuard<'_, Pool> {
    pool.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A pooled connection that is automatically returned to the pool when it goes
/// out of scope, including on early `?` returns and during panic unwinding.
/// This prevents the connection leak that previously let a handful of failed
/// queries permanently exhaust the pool.
pub struct PooledClient {
    client: Option<Client>,
}

impl Deref for PooledClient {
    type Target = Client;
    fn deref(&self) -> &Client {
        self.client
            .as_ref()
            .expect("pooled client accessed after being returned")
    }
}

impl DerefMut for PooledClient {
    fn deref_mut(&mut self) -> &mut Client {
        self.client
            .as_mut()
            .expect("pooled client accessed after being returned")
    }
}

impl Drop for PooledClient {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            // Don't return a dead connection to the pool; drop it and let the
            // pool re-establish a fresh one on demand. `is_closed` is
            // non-blocking so this is safe to call while unwinding.
            if client.is_closed() {
                log::warn!("(pool) discarding closed connection");
                return;
            }
            let mut pool = lock_pool(&CONNECTION_POOL);
            pool.connections.push_back(client);
        }
    }
}

impl ConnectionPool {
    pub fn initialise(&self, database_url: &str, pool_size: usize) -> Result<(), postgres::Error> {
        let mut pool = lock_pool(self);
        pool.database_url = database_url.to_string();
        pool.max_size = pool_size;
        for _ in pool.connections.len()..pool_size {
            match Client::connect(database_url, NoTls) {
                Ok(client) => pool.connections.push_back(client),
                Err(e) => {
                    log::error!("failed to create connection: {:?}", e);
                    return Err(e);
                }
            }
        }
        log::info!("connection pool populated, size: {}", pool_size);
        Ok(())
    }

    pub fn get_client(&self) -> Result<PooledClient, std::io::Error> {
        let (client, database_url) = {
            let mut pool = lock_pool(self);
            match pool.connections.pop_front() {
                Some(client) => (Some(client), pool.database_url.clone()),
                // Pool is momentarily empty (e.g. a connection was discarded as
                // dead). Establish a fresh one on demand rather than failing;
                // worker-thread count bounds concurrency naturally.
                None => (None, pool.database_url.clone()),
            }
        };
        let client = match client {
            Some(client) => client,
            None => {
                if database_url.is_empty() {
                    return Err(std::io::Error::other("connection pool not initialised"));
                }
                Client::connect(&database_url, NoTls).map_err(|e| {
                    log::error!("(pool) failed to establish new connection: {:?}", e);
                    std::io::Error::other("could not establish database connection")
                })?
            }
        };
        Ok(PooledClient {
            client: Some(client),
        })
    }

    /// Kept for call-site compatibility: takes ownership of the guard so the
    /// connection is returned to the pool when the guard is dropped here.
    pub fn release_client(&self, _client: PooledClient) {}
}
