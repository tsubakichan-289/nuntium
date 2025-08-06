use lru::LruCache;
use std::net::Ipv6Addr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct TimedEntry {
    last_accessed: Instant,
    value: Vec<u8>,
}

const TTL: Duration = Duration::from_secs(60 * 60);

pub(crate) type SharedKeysCache = Arc<Mutex<LruCache<Ipv6Addr, TimedEntry>>>;

pub(crate) fn create_cache() -> SharedKeysCache {
    let cap = NonZeroUsize::new(1000).unwrap();
    Arc::new(Mutex::new(LruCache::new(cap)))
}

pub(crate) fn insert_key(cache: &SharedKeysCache, addr: Ipv6Addr, key: Vec<u8>) {
    let entry = TimedEntry {
        last_accessed: Instant::now(),
        value: key,
    };
    cache.lock().unwrap().put(addr, entry);
}

pub(crate) fn get_key(cache: &SharedKeysCache, addr: &Ipv6Addr) -> Option<Vec<u8>> {
    let mut cache = cache.lock().unwrap();
    if let Some(mut entry) = cache.pop(addr) {
        if entry.last_accessed.elapsed() > TTL {
            None
        } else {
            entry.last_accessed = Instant::now();
            let value = entry.value.clone();
            cache.put(*addr, entry);
            Some(value)
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_expires_after_ttl() {
        let cache = create_cache();
        let addr = "2001:db8::1".parse().unwrap();
        insert_key(&cache, addr, vec![1, 2, 3]);
        {
            let mut guard = cache.lock().unwrap();
            let entry = guard.get_mut(&addr).unwrap();
            entry.last_accessed = Instant::now() - TTL - Duration::from_secs(1);
        }
        assert!(get_key(&cache, &addr).is_none());
    }

    #[test]
    fn entry_access_refreshes_ttl() {
        let cache = create_cache();
        let addr = "2001:db8::2".parse().unwrap();
        insert_key(&cache, addr, vec![4, 5, 6]);
        {
            let mut guard = cache.lock().unwrap();
            let entry = guard.get_mut(&addr).unwrap();
            entry.last_accessed = Instant::now() - (TTL - Duration::from_secs(1));
        }
        assert!(get_key(&cache, &addr).is_some());
        {
            let mut guard = cache.lock().unwrap();
            let entry = guard.get(&addr).unwrap();
            assert!(entry.last_accessed.elapsed() < Duration::from_secs(1));
        }
    }
}
