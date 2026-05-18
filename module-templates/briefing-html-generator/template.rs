use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let upstream = data.get("input").unwrap_or(&serde_json::Value::Null);
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let base_url = config.get("BASE_URL").and_then(|v| v.as_str()).unwrap_or("http://localhost:8000");
    let action_workflow_id = config.get("ACTION_WORKFLOW_ID").and_then(|v| v.as_str()).unwrap_or("");
    let top_priority = upstream.get("top_priority").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let todays_focus = upstream.get("todays_focus").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let incoming = upstream.get("incoming").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let quick_wins = upstream.get("quick_wins").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let day_summary = upstream.get("day_summary").and_then(|v| v.as_str()).unwrap_or("");
    // Date header: prefer a caller-supplied string (config.NOW /
    // upstream.today) so tests can pin a deterministic value, fall
    // back to the WIT `datetime::now_iso()` host import so the
    // rendered HTML always carries a real timestamp even when the
    // caller forgets to set one.
    let now = config
        .get("NOW")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            upstream
                .get("today")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| talos::core::datetime::now_iso());
    fn render_item(item: &serde_json::Value, action_wf: &str, base_url: &str) -> String {
        let key = item.get("key").and_then(|v| v.as_str()).unwrap_or("???");
        let summary = item.get("summary").and_then(|v| v.as_str()).unwrap_or("");
        let reason = item.get("reason").and_then(|v| v.as_str());
        let first_key = key.split(',').next().unwrap_or(key).trim();
        let escaped_key = html_escape(key);
        let escaped_summary = html_escape(summary);
        let escaped_first_key = html_escape(first_key);
        let escaped_base_url = html_escape(base_url);
        let reason_html = reason.map(|r| format!(
            "<span class=\"reason\">{}</span>", html_escape(r)
        )).unwrap_or_default();
        let buttons = if !action_wf.is_empty() {
            format!(
                r#"<div class="actions">
                    <button onclick="doAction('{}','{}','start')" class="btn btn-start" title="Start working">Start</button>
                    <button onclick="doAction('{}','{}','done')" class="btn btn-done" title="Mark done">Done</button>
                    <button onclick="doAction('{}','{}','review')" class="btn btn-review" title="Send to review">Review</button>
                </div>"#,
                escaped_base_url, escaped_first_key, escaped_base_url, escaped_first_key, escaped_base_url, escaped_first_key
            )
        } else {
            String::new()
        };
        format!(
            r#"<div class="item">
                <div class="item-content">
                    <span class="key">{}</span>
                    <span class="summary">{}</span>
                    {}
                </div>
                {}
            </div>"#,
            escaped_key, escaped_summary, reason_html, buttons
        )
    }
    fn render_section(title: &str, icon: &str, items: &[serde_json::Value], action_wf: &str, base_url: &str, css_class: &str) -> String {
        if items.is_empty() { return String::new(); }
        let items_html: String = items.iter().map(|i| render_item(i, action_wf, base_url)).collect();
        format!(
            r#"<section class="{}">
                <h2>{} {}</h2>
                {}
            </section>"#,
            css_class, icon, title, items_html
        )
    }
    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Morning Briefing - {date}</title>
<style>
  :root {{ --bg: #0a0a0f; --card: #12121a; --border: #1e1e2e; --text: #e0e0e8; --muted: #6b6b80; --accent: #7c5cfc; --green: #34d399; --amber: #fbbf24; --red: #f87171; --blue: #60a5fa; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); max-width: 720px; margin: 0 auto; padding: 24px 16px; }}
  header {{ margin-bottom: 32px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }}
  header h1 {{ font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }}
  header p {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1.5px; margin-top: 4px; }}
  .day-summary {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px 20px; margin-bottom: 24px; font-size: 14px; line-height: 1.6; color: var(--muted); border-left: 3px solid var(--accent); }}
  section {{ margin-bottom: 24px; }}
  section h2 {{ font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 2px; color: var(--muted); margin-bottom: 10px; }}
  .item {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 12px 16px; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center; gap: 12px; transition: border-color 0.2s; }}
  .item:hover {{ border-color: var(--accent); }}
  .item-content {{ flex: 1; min-width: 0; }}
  .key {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 11px; font-weight: 700; color: var(--accent); margin-right: 8px; }}
  .summary {{ font-size: 13px; }}
  .reason {{ display: block; font-size: 11px; color: var(--amber); margin-top: 4px; }}
  .actions {{ display: flex; gap: 4px; flex-shrink: 0; }}
  .btn {{ font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; padding: 5px 10px; border: 1px solid var(--border); border-radius: 6px; background: transparent; color: var(--muted); cursor: pointer; transition: all 0.15s; }}
  .btn:hover {{ color: var(--text); border-color: var(--text); }}
  .btn-start:hover {{ color: var(--blue); border-color: var(--blue); }}
  .btn-done:hover {{ color: var(--green); border-color: var(--green); }}
  .btn-review:hover {{ color: var(--amber); border-color: var(--amber); }}
  .btn.loading {{ opacity: 0.5; pointer-events: none; }}
  .btn.success {{ color: var(--green); border-color: var(--green); }}
  .btn.error {{ color: var(--red); border-color: var(--red); }}
  .priority {{ border-left: 3px solid var(--red); }}
  .focus {{ border-left: 3px solid var(--blue); }}
  .incoming-section {{ border-left: 3px solid var(--amber); }}
  .wins {{ border-left: 3px solid var(--green); }}
  .toast {{ position: fixed; bottom: 24px; right: 24px; background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 12px 20px; font-size: 13px; opacity: 0; transform: translateY(10px); transition: all 0.3s; z-index: 100; }}
  .toast.show {{ opacity: 1; transform: translateY(0); }}
  .toast.success {{ border-color: var(--green); color: var(--green); }}
  .toast.error {{ border-color: var(--red); color: var(--red); }}
</style>
</head>
<body>
<header>
  <h1>Morning Briefing</h1>
  <p>{date}</p>
</header>
<div class="day-summary">{summary}</div>
{priority}
{focus}
{incoming}
{wins}
<div id="toast" class="toast"></div>
<script>
const ACTION_WF = '{action_wf}';
const BASE = '{base}';
async function doAction(base, issueKey, action) {{
  const btn = event.target;
  btn.classList.add('loading');
  btn.textContent = '...';
  showToast('Transitioning ' + issueKey + ' → ' + action + '...', '');
  try {{
    const resp = await fetch(base + '/mcp/local', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{
        jsonrpc: '2.0', id: 1,
        method: 'tools/call',
        params: {{ name: 'trigger_workflow', arguments: {{
          workflow_id: ACTION_WF,
          input: {{ issue_key: issueKey, action: action }}
        }} }}
      }})
    }});
    const data = await resp.json();
    if (data.error || data.result?.isError) {{
      throw new Error(data.error?.message || data.result?.content?.[0]?.text || 'Unknown error');
    }}
    btn.classList.remove('loading');
    btn.classList.add('success');
    btn.textContent = 'Done';
    showToast(issueKey + ' → ' + action + ' ✓', 'success');
  }} catch (e) {{
    btn.classList.remove('loading');
    btn.classList.add('error');
    btn.textContent = 'Failed';
    showToast('Failed: ' + e.message, 'error');
    setTimeout(() => {{ btn.classList.remove('error'); btn.textContent = action.charAt(0).toUpperCase() + action.slice(1); }}, 3000);
  }}
}}
function showToast(msg, type) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + type;
  setTimeout(() => t.className = 'toast', 3000);
}}
</script>
</body>
</html>"#,
        date = now,
        summary = html_escape(day_summary),
        priority = render_section("Top Priority", "🔴", &top_priority, action_workflow_id, base_url, "priority"),
        focus = render_section("Today's Focus", "🔵", &todays_focus, action_workflow_id, base_url, "focus"),
        incoming = render_section("Incoming", "🟡", &incoming, action_workflow_id, base_url, "incoming-section"),
        wins = render_section("Quick Wins", "🟢", &quick_wins, action_workflow_id, base_url, "wins"),
        action_wf = html_escape(action_workflow_id),
        base = html_escape(base_url),
    );
    let output = serde_json::json!({
        "html": html,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "item_count": top_priority.len() + todays_focus.len() + incoming.len() + quick_wins.len(),
    });
    serde_json::to_string(&output).map_err(|e| e.to_string())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#39;")
}
