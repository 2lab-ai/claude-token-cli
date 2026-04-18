//! Human-facing render helpers (KST + UTC + relative clocks, tabled).

use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Asia::Seoul;
use serde_json::{json, Value};
use tabled::{settings::Style, Table, Tabled};

use crate::oauth::Bucket;

/// Row shape shown in `claude-token list`.
#[derive(Debug, Clone)]
pub struct SlotView {
    pub marker: &'static str,
    pub name: String,
    pub email: String,
    pub plan: String,
    pub expires_in: String,
    pub five_hour: String,
    pub seven_day: String,
    pub seven_day_opus: String,
}

#[derive(Tabled)]
struct SlotRow {
    #[tabled(rename = "")]
    marker: String,
    #[tabled(rename = "name")]
    name: String,
    #[tabled(rename = "email")]
    email: String,
    #[tabled(rename = "plan")]
    plan: String,
    #[tabled(rename = "expires")]
    expires: String,
    #[tabled(rename = "5h")]
    five_hour: String,
    #[tabled(rename = "7d")]
    seven_day: String,
    #[tabled(rename = "7d opus")]
    seven_day_opus: String,
}

/// Format an expiry (unix milliseconds) as `"YYYY-MM-DD HH:MM KST / HH:MM UTC (expires in …)"`.
pub fn format_expires(ts_ms: Option<i64>) -> String {
    let Some(ms) = ts_ms else {
        return "unknown".to_string();
    };
    let utc: DateTime<Utc> = match Utc.timestamp_millis_opt(ms).single() {
        Some(t) => t,
        None => return "unknown".to_string(),
    };
    let kst = utc.with_timezone(&Seoul);
    let rel = format_relative(utc, Utc::now(), "expires", "expired");
    format!(
        "{} KST / {} UTC ({})",
        kst.format("%Y-%m-%d %H:%M"),
        utc.format("%Y-%m-%d %H:%M"),
        rel
    )
}

/// Format a usage bucket (utilization + reset).
pub fn format_bucket(b: Option<&Bucket>) -> String {
    let Some(b) = b else {
        return "-".to_string();
    };
    let pct = match b.utilization {
        Some(v) => format!("{:.0}%", v),
        None => "?".to_string(),
    };
    let tail = match b.resets_at {
        Some(t) => {
            let kst = t.with_timezone(&Seoul);
            let rel = format_relative(t, Utc::now(), "in", "ago");
            format!(
                " (resets {} KST / {} UTC, {})",
                kst.format("%Y-%m-%d %H:%M"),
                t.format("%Y-%m-%d %H:%M"),
                rel
            )
        }
        None => String::new(),
    };
    format!("{pct}{tail}")
}

fn format_relative(
    target: DateTime<Utc>,
    now: DateTime<Utc>,
    future_label: &str,
    past_label: &str,
) -> String {
    let delta = target - now;
    let total = delta.num_seconds();
    let (label, secs) = if total >= 0 {
        (future_label, total)
    } else {
        (past_label, -total)
    };
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    match future_label == label {
        true => format!("{future_label} in {hours}h{mins:02}m", future_label = label),
        false => format!("{past_label} {hours}h{mins:02}m ago", past_label = label),
    }
}

/// Render the slot list as a pretty table.
pub fn list_table(entries: &[SlotView]) -> String {
    let rows: Vec<SlotRow> = entries
        .iter()
        .map(|v| SlotRow {
            marker: v.marker.to_string(),
            name: v.name.clone(),
            email: v.email.clone(),
            plan: v.plan.clone(),
            expires: v.expires_in.clone(),
            five_hour: v.five_hour.clone(),
            seven_day: v.seven_day.clone(),
            seven_day_opus: v.seven_day_opus.clone(),
        })
        .collect();
    let mut t = Table::new(rows);
    t.with(Style::psql());
    t.to_string()
}

/// Render the slot list as a JSON value (for `--format json`).
pub fn json_list(entries: &[SlotView]) -> Value {
    let arr: Vec<Value> = entries
        .iter()
        .map(|v| {
            json!({
                "active": v.marker == "*",
                "name": v.name,
                "email": v.email,
                "plan": v.plan,
                "expires": v.expires_in,
                "five_hour": v.five_hour,
                "seven_day": v.seven_day,
                "seven_day_opus": v.seven_day_opus,
            })
        })
        .collect();
    Value::Array(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_unknown() {
        assert_eq!(format_expires(None), "unknown");
    }

    #[test]
    fn expires_future() {
        let now_ms = Utc::now().timestamp_millis();
        let out = format_expires(Some(now_ms + 3_600_000));
        assert!(out.contains("KST"));
        assert!(out.contains("UTC"));
        assert!(out.contains("expires in"));
    }

    #[test]
    fn expires_past() {
        let now_ms = Utc::now().timestamp_millis();
        let out = format_expires(Some(now_ms - 3_600_000));
        assert!(out.contains("expired"));
    }

    #[test]
    fn bucket_none() {
        assert_eq!(format_bucket(None), "-");
    }

    #[test]
    fn bucket_some() {
        let b = Bucket {
            utilization: Some(42.0),
            resets_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };
        let out = format_bucket(Some(&b));
        assert!(out.contains("42%"));
        assert!(out.contains("resets"));
    }
}
