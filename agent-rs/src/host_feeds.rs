//! The two subscriptions that describe the machine rather than a capture:
//! `interface_stats` and `adapter_config`, each with the lifecycle
//! `local-agent/agent.py` gives it.
//!
//! ## What the Python agent does, which is what this does
//!
//! **`interface_stats`** (agent.py `_interface_stats_loop`): the first
//! subscriber starts a sampling task, and the task builds a **fresh** sampler -
//! so its first message is zeros, sent at once, and then one every 500 ms with
//! an entry for every interface. A second subscriber joins the running task and
//! gets its next tick. When the last one leaves the task is cancelled, so the
//! next subscriber gets a new sampler rather than one spike covering however
//! long the panel was closed.
//!
//! **`adapter_config`** (agent.py 1317-1352, `_adapter_loop`): subscribing sends
//! that client **its own** snapshot immediately, from a throwaway tracker, and
//! starts a shared ten-second poll that speaks only when something changed.
//! `refresh_adapters` subscribes the sender too, forgets the shared reading and
//! answers from the machine even when nothing changed - pressing Refresh is a
//! statement that something just did. `unsubscribe_adapters` stops the poll
//! when it was the last, forgets the reading, and sends nothing.
//!
//! This agent answered `subscribe_adapters` once and never again, answered
//! `unsubscribe_adapters` with a `state`, and sampled rates on one shared timer
//! that sent nothing on its first tick and nothing for an adapter it could not
//! join - which the app reads as that adapter's history being wiped.
//!
//! ## Why the machinery is its own module
//!
//! So the lifecycle can be held to the above without a pipe or a service: the
//! runtime is one `Outlet`, and the tests below are another.

#![cfg(windows)]

use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::adapter_config::AdapterTracker;
use crate::if_table::Rate;
use crate::protocol;

/// `INTERFACE_STATS_INTERVAL_SECONDS` in `agent.py`. The app sizes its history
/// window from the `intervalMs` the message carries.
pub const INTERFACE_STATS_INTERVAL: Duration = Duration::from_millis(500);

/// `ADAPTER_CONFIG_INTERVAL_SECONDS`: the timescale configuration actually
/// moves on - a privacy address rotating, a lease renewing, a cable moving.
pub const ADAPTER_CONFIG_INTERVAL: Duration = Duration::from_secs(10);

/// Where the feeds send, and what they ask about the agent they run inside.
pub trait Outlet: Send + Sync {
    fn send_to(&self, client: &str, message: &Value);
    /// The capture device names as the interface list holds them now - which
    /// is what `adapter_config` is narrowed to and what a new sampler samples.
    fn capture_devices(&self) -> Vec<String>;
    /// The agent is shutting down; a loop that sees this returns.
    fn stopping(&self) -> bool;
}

/// A sampler: called once per tick, answering one rate per device.
pub type Sampler = Box<dyn FnMut() -> Vec<Rate> + Send>;

/// Where the readings come from - the machine, or a test.
pub struct Sources {
    /// A new sampler over these devices, whose first call answers zeros.
    pub sampler: Box<dyn Fn(Vec<String>) -> Sampler + Send + Sync>,
    /// Every adapter's report, narrowed to these devices, as JSON.
    pub adapters: Box<dyn Fn(&[String]) -> Vec<Value> + Send + Sync>,
}

impl Sources {
    /// The machine's own.
    pub fn machine() -> Self {
        Sources {
            sampler: Box::new(|devices| {
                let mut sampler = crate::if_table::RateSampler::new(devices);
                Box::new(move || sampler.sample())
            }),
            adapters: Box::new(|keep| {
                crate::adapter_config::read_adapters(keep)
                    .iter()
                    .map(protocol::AdapterReport::to_value)
                    .collect()
            }),
        }
    }
}

/// One subscription's shared state: who is watching, and which loop is theirs.
#[derive(Default)]
struct Feed {
    /// Ordered so a fan-out's order does not depend on a hash.
    subscribers: BTreeSet<String>,
    /// Bumped whenever a loop is started or cancelled. A loop carries the value
    /// it was started with and stops the moment it differs - which is how a
    /// cancelled loop that is mid-sleep stays cancelled when a new subscriber
    /// arrives and starts another, the way `asyncio.Task.cancel` does.
    generation: u64,
    running: bool,
}

struct Guarded {
    feed: Mutex<Feed>,
    wake: Condvar,
}

impl Guarded {
    fn new() -> Self {
        Guarded { feed: Mutex::new(Feed::default()), wake: Condvar::new() }
    }

    /// Sleeps `for_`, or less if this loop is cancelled. `false` when it was.
    fn sleep(&self, generation: u64, for_: Duration) -> bool {
        let deadline = Instant::now() + for_;
        let mut held = self.feed.lock().unwrap();
        loop {
            if held.generation != generation {
                return false;
            }
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            held = self.wake.wait_timeout(held, deadline - now).unwrap().0;
        }
    }

    /// The subscribers to send to, or `None` when this loop should end.
    fn watchers(&self, generation: u64, outlet: &dyn Outlet) -> Option<Vec<String>> {
        let mut held = self.feed.lock().unwrap();
        if held.generation != generation {
            return None;
        }
        if held.subscribers.is_empty() || outlet.stopping() {
            held.running = false;
            return None;
        }
        Some(held.subscribers.iter().cloned().collect())
    }

    /// Adds a subscriber. `Some(generation)` when there was no loop and the
    /// caller must start one - `_ensure_*_task`.
    fn add(&self, client: &str) -> Option<u64> {
        let mut held = self.feed.lock().unwrap();
        held.subscribers.insert(client.to_string());
        if held.running {
            return None;
        }
        held.running = true;
        held.generation += 1;
        Some(held.generation)
    }

    /// Removes a subscriber, and cancels the loop if none is left -
    /// `_stop_*_task_if_idle`. `true` when a loop was cancelled.
    fn remove(&self, client: &str) -> bool {
        let mut held = self.feed.lock().unwrap();
        held.subscribers.remove(client);
        if held.subscribers.is_empty() && held.running {
            held.running = false;
            held.generation += 1;
            self.wake.notify_all();
            return true;
        }
        false
    }
}

/// Both feeds, for the whole agent.
pub struct HostFeeds {
    sources: Sources,
    rates: Guarded,
    adapters: Guarded,
    /// The shared reading the ten-second poll compares against.
    tracker: Mutex<AdapterTracker>,
    rate_interval: Duration,
    adapter_interval: Duration,
}

impl HostFeeds {
    pub fn new(sources: Sources) -> Arc<Self> {
        Self::with_intervals(sources, INTERFACE_STATS_INTERVAL, ADAPTER_CONFIG_INTERVAL)
    }

    pub fn with_intervals(sources: Sources, rate: Duration, adapter: Duration) -> Arc<Self> {
        Arc::new(HostFeeds {
            sources,
            rates: Guarded::new(),
            adapters: Guarded::new(),
            tracker: Mutex::new(AdapterTracker::new()),
            rate_interval: rate,
            adapter_interval: adapter,
        })
    }

    // --- interface_stats ----------------------------------------------------

    /// `subscribe_interface_stats`. Sends nothing itself: a new loop sends its
    /// first tick at once, and a running one sends its next.
    pub fn subscribe_interface_stats(self: &Arc<Self>, outlet: &Arc<dyn Outlet>, client: &str) {
        if let Some(generation) = self.rates.add(client) {
            let (feeds, outlet) = (Arc::clone(self), Arc::clone(outlet));
            thread::spawn(move || feeds.rate_loop(&*outlet, generation));
        }
    }

    pub fn unsubscribe_interface_stats(&self, client: &str) {
        self.rates.remove(client);
    }

    fn rate_loop(&self, outlet: &dyn Outlet, generation: u64) {
        // Built here, per loop, over the devices as they are now.
        let mut sample = (self.sources.sampler)(outlet.capture_devices());
        let interval_ms = self.rate_interval.as_millis() as u32;
        loop {
            let Some(watchers) = self.rates.watchers(generation, outlet) else { return };
            let message = protocol::interface_stats(interval_ms, &sample());
            for watcher in watchers {
                outlet.send_to(&watcher, &message);
            }
            if !self.rates.sleep(generation, self.rate_interval) {
                return;
            }
        }
    }

    // --- adapter_config -----------------------------------------------------

    /// `subscribe_adapters`: this client's own snapshot now, then the poll.
    ///
    /// From a throwaway tracker, so it always speaks and does not disturb the
    /// shared reading - which starts empty, so the poll's first tick sends a
    /// snapshot too, exactly as `agent.py`'s does.
    pub fn subscribe_adapters(self: &Arc<Self>, outlet: &Arc<dyn Outlet>, client: &str) {
        let generation = self.adapters.add(client);
        let keep = outlet.capture_devices();
        if let Some(snapshot) = AdapterTracker::new().observe((self.sources.adapters)(&keep)) {
            outlet.send_to(client, &snapshot);
        }
        self.start_adapter_loop(outlet, generation);
    }

    /// `refresh_adapters`: subscribes the sender, forgets the shared reading,
    /// and answers from the machine even when nothing changed.
    pub fn refresh_adapters(self: &Arc<Self>, outlet: &Arc<dyn Outlet>, client: &str) {
        let generation = self.adapters.add(client);
        let keep = outlet.capture_devices();
        let answer = {
            let mut tracker = self.tracker.lock().unwrap();
            tracker.reset();
            tracker.observe((self.sources.adapters)(&keep))
        };
        if let Some(answer) = answer {
            outlet.send_to(client, &answer);
        }
        self.start_adapter_loop(outlet, generation);
    }

    /// `unsubscribe_adapters`. Sends nothing.
    pub fn unsubscribe_adapters(&self, client: &str) {
        if self.adapters.remove(client) {
            // The next subscriber gets a snapshot of its own, but the shared
            // reading must not carry a configuration from before the gap into
            // the first comparison after it - everything that changed in
            // between would stay unsaid.
            self.tracker.lock().unwrap().reset();
        }
    }

    fn start_adapter_loop(self: &Arc<Self>, outlet: &Arc<dyn Outlet>, generation: Option<u64>) {
        if let Some(generation) = generation {
            let (feeds, outlet) = (Arc::clone(self), Arc::clone(outlet));
            thread::spawn(move || feeds.adapter_loop(&*outlet, generation));
        }
    }

    fn adapter_loop(&self, outlet: &dyn Outlet, generation: u64) {
        loop {
            if !self.adapters.sleep(generation, self.adapter_interval) {
                return;
            }
            if self.adapters.watchers(generation, outlet).is_none() {
                return;
            }
            let keep = outlet.capture_devices();
            let reading = (self.sources.adapters)(&keep);
            // `None` is nothing changed, which is almost every poll: this is
            // configuration, not traffic.
            let Some(message) = self.tracker.lock().unwrap().observe(reading) else { continue };
            let Some(watchers) = self.adapters.watchers(generation, outlet) else { return };
            for watcher in watchers {
                outlet.send_to(&watcher, &message);
            }
        }
    }

    // --- both ---------------------------------------------------------------

    /// A client's pipe closed: out of both feeds, and each loop stops if that
    /// was its last subscriber - what `handle_disconnect` does, so a closed
    /// window leaves nothing sampling.
    pub fn client_gone(&self, client: &str) {
        self.unsubscribe_interface_stats(client);
        self.unsubscribe_adapters(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// An outlet that records what it was asked to send. No pipe, no frames.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<(String, Value)>>,
        stopping: AtomicBool,
    }

    impl Outlet for Recorder {
        fn send_to(&self, client: &str, message: &Value) {
            self.sent.lock().unwrap().push((client.to_string(), message.clone()));
        }
        fn capture_devices(&self) -> Vec<String> {
            vec![r"\Device\NPF_{A}".into(), r"\Device\NPF_Loopback".into()]
        }
        fn stopping(&self) -> bool {
            self.stopping.load(Ordering::SeqCst)
        }
    }

    impl Recorder {
        fn to(&self, client: &str, kind: &str) -> Vec<Value> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, m)| c == client && m["type"] == kind)
                .map(|(_, m)| m.clone())
                .collect()
        }
        fn clear(&self) {
            self.sent.lock().unwrap().clear();
        }
    }

    /// Waits for `until` to hold, for up to two seconds.
    fn eventually(until: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if until() {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        until()
    }

    const RATE: Duration = Duration::from_millis(40);
    const POLL: Duration = Duration::from_millis(60);

    /// A sampler source that counts how many samplers were built, and whose
    /// samplers answer zeros first and a constant after - `RateSampler`'s shape.
    fn counting() -> (Sources, Arc<AtomicUsize>, Arc<Mutex<Vec<Value>>>) {
        let built = Arc::new(AtomicUsize::new(0));
        let reading = Arc::new(Mutex::new(vec![serde_json::json!({ "id": "A" })]));
        let (b, r) = (Arc::clone(&built), Arc::clone(&reading));
        let sources = Sources {
            sampler: Box::new(move |devices| {
                b.fetch_add(1, Ordering::SeqCst);
                let mut first = true;
                Box::new(move || {
                    let value = if std::mem::replace(&mut first, false) { 0.0 } else { 3.0 };
                    devices
                        .iter()
                        .map(|d| Rate { name: d.clone(), packets_per_sec: value, bytes_per_sec: value })
                        .collect()
                })
            }),
            adapters: Box::new(move |_keep| r.lock().unwrap().clone()),
        };
        (sources, built, reading)
    }

    #[test]
    fn rates_start_at_once_with_zeros_for_every_device_and_keep_ticking() {
        let (sources, built, _) = counting();
        let feeds = HostFeeds::with_intervals(sources, RATE, POLL);
        let recorder = Arc::new(Recorder::default());
        let outlet: Arc<dyn Outlet> = recorder.clone();

        feeds.subscribe_interface_stats(&outlet, "a");
        assert!(eventually(|| !recorder.to("a", "interface_stats").is_empty()), "no first tick");
        let first = &recorder.to("a", "interface_stats")[0];
        assert_eq!(first["intervalMs"], RATE.as_millis() as u64);
        let entries = first["interfaces"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "one entry per device, loopback included");
        assert!(entries.iter().all(|e| e["packetsPerSec"] == 0.0 && e["bytesPerSec"] == 0.0));
        assert!(eventually(|| recorder.to("a", "interface_stats").len() >= 3), "it stopped ticking");

        // A second subscriber joins the running loop rather than starting one.
        feeds.subscribe_interface_stats(&outlet, "b");
        assert!(eventually(|| !recorder.to("b", "interface_stats").is_empty()));
        assert_eq!(built.load(Ordering::SeqCst), 1, "one loop, one sampler");
        assert_ne!(recorder.to("b", "interface_stats")[0]["interfaces"][0]["packetsPerSec"], 0.0,
            "a joiner gets the running sampler's next tick, not a fresh zero");
        feeds.client_gone("a");
        feeds.client_gone("b");
    }

    #[test]
    fn the_last_unsubscribe_stops_rates_and_the_next_subscriber_gets_a_new_sampler() {
        let (sources, built, _) = counting();
        let feeds = HostFeeds::with_intervals(sources, RATE, POLL);
        let recorder = Arc::new(Recorder::default());
        let outlet: Arc<dyn Outlet> = recorder.clone();

        feeds.subscribe_interface_stats(&outlet, "a");
        assert!(eventually(|| recorder.to("a", "interface_stats").len() >= 2));
        feeds.unsubscribe_interface_stats("a");
        thread::sleep(RATE * 2);
        recorder.clear();
        thread::sleep(RATE * 4);
        assert!(recorder.to("a", "interface_stats").is_empty(), "it kept sampling for nobody");

        // Straight back in: a new loop, a new sampler, and zeros again.
        feeds.subscribe_interface_stats(&outlet, "a");
        assert!(eventually(|| !recorder.to("a", "interface_stats").is_empty()));
        assert_eq!(built.load(Ordering::SeqCst), 2);
        assert_eq!(recorder.to("a", "interface_stats")[0]["interfaces"][0]["packetsPerSec"], 0.0);
        feeds.client_gone("a");
    }

    #[test]
    fn a_quick_unsubscribe_and_resubscribe_runs_one_loop_not_two() {
        let (sources, built, _) = counting();
        let feeds = HostFeeds::with_intervals(sources, Duration::from_millis(200), POLL);
        let recorder = Arc::new(Recorder::default());
        let outlet: Arc<dyn Outlet> = recorder.clone();

        feeds.subscribe_interface_stats(&outlet, "a");
        assert!(eventually(|| !recorder.to("a", "interface_stats").is_empty()));
        // Inside the first loop's sleep: cancelled, then replaced.
        feeds.unsubscribe_interface_stats("a");
        feeds.subscribe_interface_stats(&outlet, "a");
        assert!(eventually(|| built.load(Ordering::SeqCst) == 2));
        recorder.clear();
        thread::sleep(Duration::from_millis(700));
        let ticks = recorder.to("a", "interface_stats").len();
        // One loop at 200 ms is three or four ticks in 700 ms; two would be
        // six or more.
        assert!((2..=5).contains(&ticks), "{ticks} ticks - the cancelled loop is still running");
        feeds.client_gone("a");
    }

    #[test]
    fn subscribing_to_adapters_answers_at_once_then_polls_and_goes_quiet() {
        let (sources, _, reading) = counting();
        let feeds = HostFeeds::with_intervals(sources, RATE, POLL);
        let recorder = Arc::new(Recorder::default());
        let outlet: Arc<dyn Outlet> = recorder.clone();

        feeds.subscribe_adapters(&outlet, "a");
        // The snapshot is sent before the call returns.
        assert_eq!(recorder.to("a", "adapter_config").len(), 1);
        // The shared reading starts empty, so the poll's first tick speaks too.
        assert!(eventually(|| recorder.to("a", "adapter_config").len() == 2));
        // And then nothing, for as long as nothing changes.
        thread::sleep(POLL * 4);
        assert_eq!(recorder.to("a", "adapter_config").len(), 2, "it spoke with nothing to say");

        *reading.lock().unwrap() = vec![serde_json::json!({ "id": "A", "mtu": 1500 })];
        assert!(eventually(|| recorder.to("a", "adapter_config").len() == 3), "a change was not sent");
        assert_eq!(recorder.to("a", "adapter_config")[2]["adapters"][0]["mtu"], 1500);
        feeds.client_gone("a");
    }

    #[test]
    fn refresh_subscribes_the_sender_and_answers_even_when_nothing_changed() {
        let (sources, _, _) = counting();
        let feeds = HostFeeds::with_intervals(sources, RATE, POLL);
        let recorder = Arc::new(Recorder::default());
        let outlet: Arc<dyn Outlet> = recorder.clone();

        feeds.subscribe_adapters(&outlet, "a");
        assert!(eventually(|| recorder.to("a", "adapter_config").len() == 2));
        feeds.refresh_adapters(&outlet, "b");
        assert_eq!(recorder.to("b", "adapter_config").len(), 1, "refresh answers at once");
        feeds.refresh_adapters(&outlet, "b");
        assert_eq!(recorder.to("b", "adapter_config").len(), 2, "...even with nothing changed");
        // And "b" is now subscribed: a change reaches it.
        feeds.unsubscribe_adapters("a");
        recorder.clear();
        feeds.refresh_adapters(&outlet, "b");
        recorder.clear();
        thread::sleep(POLL * 3);
        assert!(recorder.to("a", "adapter_config").is_empty(), "an unsubscribed client was sent to");
        feeds.client_gone("b");
    }

    #[test]
    fn unsubscribing_from_adapters_sends_nothing_and_stops_the_poll() {
        let (sources, _, reading) = counting();
        let feeds = HostFeeds::with_intervals(sources, RATE, POLL);
        let recorder = Arc::new(Recorder::default());
        let outlet: Arc<dyn Outlet> = recorder.clone();

        feeds.subscribe_adapters(&outlet, "a");
        recorder.clear();
        feeds.unsubscribe_adapters("a");
        assert!(recorder.sent.lock().unwrap().is_empty(), "unsubscribe must not answer");
        *reading.lock().unwrap() = vec![serde_json::json!({ "id": "B" })];
        thread::sleep(POLL * 4);
        assert!(recorder.sent.lock().unwrap().is_empty(), "the poll outlived its last subscriber");
    }

    #[test]
    fn a_stopping_agent_ends_both_loops() {
        let (sources, _, _) = counting();
        let feeds = HostFeeds::with_intervals(sources, RATE, POLL);
        let recorder = Arc::new(Recorder::default());
        let outlet: Arc<dyn Outlet> = recorder.clone();
        feeds.subscribe_interface_stats(&outlet, "a");
        feeds.subscribe_adapters(&outlet, "a");
        assert!(eventually(|| !recorder.to("a", "interface_stats").is_empty()));
        recorder.stopping.store(true, Ordering::SeqCst);
        thread::sleep(POLL * 2);
        recorder.clear();
        thread::sleep(POLL * 4);
        assert!(recorder.sent.lock().unwrap().is_empty(), "a loop kept running into shutdown");
    }
}
