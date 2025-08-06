use lru::LruCache;
use std::net::Ipv6Addr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

pub type SharedKeysCache = Arc<Mutex<LruCache<Ipv6Addr, Vec<u8>>>>;

pub fn create_cache() -> SharedKeysCache {
    let cap = NonZeroUsize::new(1000).unwrap();
    Arc::new(Mutex::new(LruCache::new(cap)))
}

pub fn insert_key(cache: &SharedKeysCache, addr: Ipv6Addr, key: Vec<u8>) {
    cache.lock().unwrap().put(addr, key);
}

pub fn get_key(cache: &SharedKeysCache, addr: &Ipv6Addr) -> Option<Vec<u8>> {
    cache.lock().unwrap().get(addr).cloned()
}
