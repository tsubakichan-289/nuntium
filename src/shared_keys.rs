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

pub(crate) struct KeyCache {
    ttl: Duration,
    cache: LruCache<Ipv6Addr, TimedEntry>,
}

pub(crate) type SharedKeysCache = Arc<Mutex<KeyCache>>;

pub(crate) fn create_cache(ttl_secs: u64, max_keys: usize) -> SharedKeysCache {
    let cap = NonZeroUsize::new(max_keys).expect("max_keys must be greater than zero");
    let ttl = Duration::from_secs(ttl_secs);
    Arc::new(Mutex::new(KeyCache {
        ttl,
        cache: LruCache::new(cap),
    }))
}

pub(crate) fn insert_key(cache: &SharedKeysCache, addr: Ipv6Addr, key: Vec<u8>) {
    let entry = TimedEntry {
        last_accessed: Instant::now(),
        value: key,
    };
    cache.lock().unwrap().cache.put(addr, entry);
}

pub(crate) fn get_key(cache: &SharedKeysCache, addr: &Ipv6Addr) -> Option<Vec<u8>> {
    let mut cache = cache.lock().unwrap();
    if let Some(mut entry) = cache.cache.pop(addr) {
        if entry.last_accessed.elapsed() > cache.ttl {
            None
        } else {
            entry.last_accessed = Instant::now();
            let value = entry.value.clone();
            cache.cache.put(*addr, entry);
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
        let ttl_secs = 3600;
        let ttl = Duration::from_secs(ttl_secs);
        let cache = create_cache(ttl_secs, 1000);
        let addr = "2001:db8::1".parse().unwrap();
        insert_key(&cache, addr, vec![1, 2, 3]);
        {
            let mut guard = cache.lock().unwrap();
            let entry = guard.cache.get_mut(&addr).unwrap();
            entry.last_accessed = Instant::now() - ttl - Duration::from_secs(1);
        }
        assert!(get_key(&cache, &addr).is_none());
    }

    #[test]
    fn entry_access_refreshes_ttl() {
        let ttl_secs = 3600;
        let ttl = Duration::from_secs(ttl_secs);
        let cache = create_cache(ttl_secs, 1000);
        let addr = "2001:db8::2".parse().unwrap();
        insert_key(&cache, addr, vec![4, 5, 6]);
        {
            let mut guard = cache.lock().unwrap();
            let entry = guard.cache.get_mut(&addr).unwrap();
            entry.last_accessed = Instant::now() - (ttl - Duration::from_secs(1));
        }
        assert!(get_key(&cache, &addr).is_some());
        {
            let mut guard = cache.lock().unwrap();
            let entry = guard.cache.get(&addr).unwrap();
            assert!(entry.last_accessed.elapsed() < Duration::from_secs(1));
        }
    }
}
