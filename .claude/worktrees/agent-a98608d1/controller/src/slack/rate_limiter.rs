use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Slack-specific rate limiter that tracks per-channel and global rates
pub struct SlackRateLimiter {
    // Track (trigger_id, channel_id) -> (count, window_start)
    channel_limits: HashMap<(String, String), (usize, Instant)>,
    // Track trigger_id -> (count, window_start)
    global_limits: HashMap<String, (usize, Instant)>,
    window_duration: Duration,
}

impl Default for SlackRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl SlackRateLimiter {
    pub fn new() -> Self {
        Self {
            channel_limits: HashMap::new(),
            global_limits: HashMap::new(),
            window_duration: Duration::from_secs(60),
        }
    }

    /// Check if a Slack event should be rate limited
    /// Returns true if the event is allowed, false if it should be rate limited
    pub fn allow(
        &mut self,
        trigger_id: &str,
        channel_id: Option<&str>,
        max_per_minute: usize,
        max_per_channel: Option<usize>,
    ) -> bool {
        let now = Instant::now();
        self.cleanup_old_entries(now);

        // Check global limit for this trigger
        let global_key = trigger_id.to_string();
        let (global_count, global_start) = self
            .global_limits
            .entry(global_key.clone())
            .or_insert((0, now));

        // Reset window if expired
        if now.duration_since(*global_start) >= self.window_duration {
            *global_count = 0;
            *global_start = now;
        }

        // Check global limit
        if *global_count >= max_per_minute {
            return false;
        }

        // Check per-channel limit if specified
        if let (Some(channel), Some(max_channel)) = (channel_id, max_per_channel) {
            let channel_key = (trigger_id.to_string(), channel.to_string());
            let (channel_count, channel_start) =
                self.channel_limits.entry(channel_key).or_insert((0, now));

            // Reset window if expired
            if now.duration_since(*channel_start) >= self.window_duration {
                *channel_count = 0;
                *channel_start = now;
            }

            // Check per-channel limit
            if *channel_count >= max_channel {
                return false;
            }

            // Increment both counters
            *channel_count += 1;
        }

        // Increment global counter
        *global_count += 1;

        true
    }

    /// Clean up expired entries to prevent memory leaks
    fn cleanup_old_entries(&mut self, now: Instant) {
        self.global_limits
            .retain(|_, (_, start)| now.duration_since(*start) < self.window_duration * 2);

        self.channel_limits
            .retain(|_, (_, start)| now.duration_since(*start) < self.window_duration * 2);
    }
}
