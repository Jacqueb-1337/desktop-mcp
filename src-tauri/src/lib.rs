mod local_agent;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    env, fs,
    path::PathBuf,
    sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, PhysicalPosition, State, UserAttentionType, WindowEvent,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    remote_access: bool,
    approval_mode: String,
    approval_duration: String,
    administrator_commands: bool,
    ask_destructive: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            remote_access: false,
            approval_mode: "ask".into(),
            approval_duration: "60".into(),
            administrator_commands: false,
            ask_destructive: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Activity {
    timestamp: u64,
    description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Persisted {
    settings: Settings,
    history: Vec<Activity>,
}

struct AppState {
    persisted: Mutex<Persisted>,
    file: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
struct SettingsPatch {
    remote_access: Option<bool>,
    approval_mode: Option<String>,
    approval_duration: Option<String>,
    administrator_commands: Option<bool>,
    ask_destructive: Option<bool>,
}

#[derive(Serialize)]
struct Snapshot {
    host_name: String,
    platform: String,
    connection: &'static str,
    pairing_available: bool,
    elevation_available: bool,
    settings: Settings,
    history: Vec<Activity>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn host_name() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "This computer".into())
}

fn snapshot(data: &Persisted) -> Snapshot {
    Snapshot {
        host_name: host_name(),
        platform: if cfg!(windows) { "Windows" } else { "Linux" }.into(),
        connection: "not_paired",
        pairing_available: true,
        elevation_available: false,
        settings: data.settings.clone(),
        history: data.history.iter().rev().take(40).cloned().collect(),
    }
}

fn log(data: &mut Persisted, message: &str) {
    data.history.push(Activity {
        timestamp: now(),
        description: message.into(),
    });
    if data.history.len() > 100 {
        let remove = data.history.len() - 100;
        data.history.drain(..remove);
    }
}

fn save(state: &AppState, data: &Persisted) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(data).map_err(|e| e.to_string())?;
    if let Some(parent) = state.file.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&state.file, bytes).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_app_state(state: State<'_, AppState>) -> Result<Snapshot, String> {
    let data = state.persisted.lock().map_err(|e| e.to_string())?;
    Ok(snapshot(&data))
}

#[tauri::command]
fn update_settings(state: State<'_, AppState>, changes: SettingsPatch) -> Result<Snapshot, String> {
    let mut guard = state.persisted.lock().map_err(|e| e.to_string())?;
    let mut updated = guard.clone();
    let policy_changed = changes.approval_mode.is_some() || changes.approval_duration.is_some();

    if let Some(value) = changes.remote_access {
        let dir=state.file.parent().ok_or("Missing app directory")?;
        match local_agent::request(dir,"set_remote_readonly",json!({"enabled":value})) {
            Ok(_)=>{},
            Err(ref e) if !value && local_agent::is_agent_offline(e)=>{},
            Err(e)=>return Err(format!("Cannot update remote access: {e}")),
        }
        updated.settings.remote_access = value;
        log(
            &mut updated,
            if value {
                "Remote access preference enabled"
            } else {
                "Remote access disabled"
            },
        );
    }
    if let Some(value) = changes.approval_mode {
        if !["ask", "auto", "read_only"].contains(&value.as_str()) {
            return Err("Unsupported approval mode".into());
        }
        updated.settings.approval_mode = value.clone();
        log(&mut updated, &format!("Approval mode set to {value}"));
    }
    if let Some(value) = changes.approval_duration {
        if !["30", "60", "240", "persistent"].contains(&value.as_str()) {
            return Err("Unsupported approval duration".into());
        }
        updated.settings.approval_duration = value;
        log(&mut updated, "Approval duration updated");
    }
    if changes.administrator_commands == Some(true) {
        // Never elevate using an unprotected webview IPC command.
        return Err(
            "Administrator helper is not installed. Elevated access is unavailable in this build."
                .into(),
        );
    }
    if changes.administrator_commands == Some(false) {
        updated.settings.administrator_commands = false;
        log(&mut updated, "Administrator commands disabled");
    }
    if let Some(value) = changes.ask_destructive {
        if !value {
            return Err("Destructive-operation approval cannot be disabled in this build.".into());
        }
        updated.settings.ask_destructive = value;
    }

    // The tray preference is not an authorization grant by itself.
    // Only enable autonomous writes when the local agent confirms them.
    if policy_changed {
        let dir = state.file.parent().ok_or("Missing application config directory")?;
        let request = json!({
            "mode":updated.settings.approval_mode,
            "duration":updated.settings.approval_duration
        });
        match local_agent::request(dir, "set_policy", request) {
            Ok(_) => log(&mut updated, "Local agent approval policy updated"),
            Err(ref e) if local_agent::is_agent_offline(e) && updated.settings.approval_mode != "auto" => {
                log(&mut updated, "Approval preference saved while local agent is offline");
            }
            Err(e) => return Err(format!("Local agent policy was not applied: {e}")),
        };
    }

    save(&state, &updated)?;
    *guard = updated;
    Ok(snapshot(&guard))
}

#[tauri::command]
fn get_local_agent_status(state: State<'_, AppState>) -> Value {
    let Some(dir) = state.file.parent() else {
        return json!({"running":false,"error":"Missing app config directory"});
    };
    let mut info = local_agent::request(dir, "status", json!({}))
        .unwrap_or_else(|error| json!({"running":false,"error":error}));
    info["unattended_service_installed"] = json!(unattended_service_path().is_some());
    info
}

fn unattended_service_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let path = PathBuf::from(env::var_os("ProgramFiles")?)
            .join("DesktopMCP").join("DesktopMCPService.exe");
        path.is_file().then_some(path)
    }
    #[cfg(not(windows))]
    { None }
}

#[tauri::command]
fn open_unattended_controls(action: String) -> Result<(), String> {
    let argument = match action.as_str() {
        "grant" => "--grant",
        "revoke" => "--revoke",
        _ => return Err("Unsupported unattended access action".into()),
    };
    let path = unattended_service_path().ok_or("Unattended service is unavailable")?;
    std::process::Command::new(path).arg(argument).spawn()
        .map(|_| ()).map_err(|error| error.to_string())
}

fn pairing_call(state: State<'_, AppState>, method: &str, payload: Value) -> Result<Value, String> {
    let dir = state.file.parent().ok_or("Missing application config directory")?;
    local_agent::request(dir, method, payload)
}

#[tauri::command]
fn get_pairing_state(state: State<'_, AppState>) -> Result<Value, String> {
    pairing_call(state, "pair_list", json!({}))
}

#[tauri::command]
fn create_pair_invitation(state: State<'_, AppState>) -> Result<Value, String> {
    pairing_call(state, "pair_create_invite", json!({}))
}

#[tauri::command]
fn prepare_pair_join(state: State<'_, AppState>, invitation: Value, name: String) -> Result<Value, String> {
    pairing_call(state, "pair_prepare_join", json!({"invitation":invitation,"name":name}))
}

#[tauri::command]
fn accept_pair_join(state: State<'_, AppState>, join_request: Value) -> Result<Value, String> {
    pairing_call(state, "pair_accept_join", json!({"join_request":join_request}))
}

#[tauri::command]
fn finalize_pair_join(state: State<'_, AppState>, receipt: Value, name: String) -> Result<Value, String> {
    pairing_call(state, "pair_finalize_join", json!({"receipt":receipt,"name":name}))
}

#[tauri::command]
fn revoke_paired_peer(state: State<'_, AppState>, host_id: String) -> Result<Value, String> {
    pairing_call(state, "pair_revoke", json!({"host_id":host_id}))
}

#[tauri::command]
fn cancel_pair_invitation(state: State<'_, AppState>) -> Result<Value, String> {
    pairing_call(state, "pair_cancel", json!({}))
}

#[tauri::command]
fn get_pending_approvals(state: State<'_, AppState>) -> Result<Value, String> {
    pairing_call(state, "approval_list", json!({}))
}

#[tauri::command]
fn set_admin_command_grant(state: State<'_, AppState>, duration: Option<String>) -> Result<Value, String> {
    pairing_call(state, "set_admin_command", json!({"duration":duration}))
}

#[tauri::command]
fn review_remote_request(
    state: State<'_, AppState>,
    request_id: String,
    nonce: String,
    request_hash: String,
    decision: String,
) -> Result<Value, String> {
    if !matches!(decision.as_str(), "approve" | "deny") {
        return Err("Unsupported review decision".into());
    }
    // Exact executable requests receive a one-use grant; legacy frames remain review-only.
    pairing_call(state,"approval_decide",json!({
        "request_id":request_id,"nonce":nonce,"request_hash":request_hash,"decision":decision
    }))
}
#[tauri::command]
fn revoke_access(state: State<'_, AppState>) -> Result<Snapshot, String> {
    let dir = state.file.parent().ok_or("Missing application config directory")?;
    match local_agent::request(dir, "revoke", json!({})) {
        Ok(_) => {},
        Err(ref e) if local_agent::is_agent_offline(e) => {},
        Err(e) => return Err(format!("Cannot confirm local agent revocation: {e}"))
    }
    let mut guard = state.persisted.lock().map_err(|e| e.to_string())?;
    let mut updated = guard.clone();
    updated.settings.remote_access = false;
    updated.settings.administrator_commands = false;
    updated.settings.approval_mode = "ask".into();
    log(&mut updated, "Remote access revoked locally");
    save(&state, &updated)?;
    *guard = updated;
    Ok(snapshot(&guard))
}

#[tauri::command]
fn hide_popup(window: tauri::WebviewWindow) -> Result<(), String> {
    window.hide().map_err(|e| e.to_string())
}

fn tray_icon() -> Image<'static> {
    let size = 24usize;
    let mut rgba = vec![0u8; size * size * 4];
    let mut plot = |x: usize, y: usize, rgb: [u8; 3]| {
        if x < size && y < size {
            let i = (y * size + x) * 4;
            rgba[i..i + 3].copy_from_slice(&rgb);
            rgba[i + 3] = 255;
        }
    };
    // Simple native monitor silhouette, with a small green status indicator.
    for y in 4..16 {
        for x in 2..21 {
            if x < 4 || x > 18 || y < 6 || y > 13 {
                plot(x, y, [239, 240, 241]);
            }
        }
    }
    for x in 10..13 {
        for y in 16..19 {
            plot(x, y, [239, 240, 241]);
        }
    }
    for x in 7..16 {
        plot(x, 19, [239, 240, 241]);
    }
    for y in 15..21 {
        for x in 17..23 {
            let dx = x as i32 - 20;
            let dy = y as i32 - 18;
            if dx * dx + dy * dy <= 8 {
                plot(x, y, [72, 185, 111]);
            }
        }
    }
    Image::new_owned(rgba, size as u32, size as u32)
}

fn show_popup(app: &tauri::AppHandle, point: Option<PhysicalPosition<f64>>) {
    let Some(window) = app.get_webview_window("tray") else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        return;
    }

    if let Some(point) = point {
        if let (Ok(size), Ok(Some(monitor))) = (window.outer_size(), window.current_monitor()) {
            let origin = monitor.position();
            let bounds = monitor.size();
            let min_x = origin.x + 10;
            let max_x = (origin.x + bounds.width as i32 - size.width as i32 - 10).max(min_x);
            let min_y = origin.y + 10;
            let max_y = (origin.y + bounds.height as i32 - size.height as i32 - 10).max(min_y);

            let x = (point.x as i32 - size.width as i32 + 36).clamp(min_x, max_x);
            let above = point.y as i32 - size.height as i32 - 14;
            let below = point.y as i32 + 14;
            let preferred_y = if above < min_y { below } else { above };
            let y = preferred_y.clamp(min_y, max_y);
            let _ = window.set_position(PhysicalPosition::new(x, y));
        }
    }
    let _ = window.show();
    let _ = window.set_focus();
}

const RELEASE_API: &str = "https://api.github.com/repos/Jacqueb-1337/desktop-mcp/releases/latest";
const RELEASE_PAGE: &str = "https://github.com/Jacqueb-1337/desktop-mcp/releases/latest";

fn stable_version(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.strip_prefix('v').unwrap_or(value).split('.');
    let mut next = || {
        let part = parts.next()?;
        let number = part.parse::<u32>().ok()?;
        (part == number.to_string()).then_some(number)
    };
    let version = (next()?, next()?, next()?);
    parts.next().is_none().then_some(version)
}

fn fetch_release(current: &str) -> Result<Value, String> {
    #[cfg(windows)]
    let mut request = {
        use std::os::windows::process::CommandExt;
        let system = PathBuf::from(env::var_os("SystemRoot").ok_or("Windows system directory unavailable")?);
        let mut request = std::process::Command::new(system.join("System32").join("curl.exe"));
        request.creation_flags(0x08000000);
        request
    };
    #[cfg(not(windows))]
    let mut request = std::process::Command::new("curl");
    let reply = request.args([
        "--disable", "--fail", "--silent", "--max-time", "8", "--proto", "=https",
        "--max-filesize", "2097152", "--user-agent", "Desktop-MCP",
        "--header", "Accept: application/vnd.github+json", RELEASE_API,
    ]).output().map_err(|_| "Could not start the release check")?;
    if !reply.status.success() {
        return Err("GitHub release check is unavailable".into());
    }
    let release: Value = serde_json::from_slice(&reply.stdout).map_err(|_| "Invalid GitHub release response")?;
    let tag = release["tag_name"].as_str().ok_or("Release version is missing")?;
    let latest = stable_version(tag).ok_or("Release version is not a stable version")?;
    let installed = stable_version(current).ok_or("Installed version is invalid")?;
    Ok(json!({"current":current,"latest":tag,"available":latest>installed}))
}

#[tauri::command]
async fn check_for_updates(app: tauri::AppHandle) -> Result<Value, String> {
    let current = app.package_info().version.to_string();
    tauri::async_runtime::spawn_blocking(move || fetch_release(&current))
        .await.map_err(|error| error.to_string())?
}

#[tauri::command]
fn open_release_page() -> Result<(), String> {
    #[cfg(windows)]
    let mut browser = std::process::Command::new("explorer.exe");
    #[cfg(not(windows))]
    let mut browser = std::process::Command::new("xdg-open");
    browser.arg(RELEASE_PAGE).spawn().map(|_| ()).map_err(|error| error.to_string())
}

pub fn run() {
    // Opt-in smoke-test flag. Normal launches remain tray-only and hidden.
    let show_on_launch = env::args_os().any(|arg| arg == "--show-popup");
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_app_state,
            get_local_agent_status,
            get_pairing_state,
            get_pending_approvals,
            review_remote_request,
            set_admin_command_grant,
            open_unattended_controls,
            check_for_updates,
            open_release_page,
            create_pair_invitation,
            prepare_pair_join,
            accept_pair_join,
            finalize_pair_join,
            revoke_paired_peer,
            cancel_pair_invitation,
            update_settings,
            revoke_access,
            hide_popup
        ])
        .setup(move |app| {
            let file = app.path().app_config_dir()?.join("settings.json");
            let persisted = fs::read(&file)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Persisted>(&bytes).ok())
                .unwrap_or_default();
            app.manage(AppState {
                file,
                persisted: Mutex::new(persisted),
            });

            // Poll authenticated loopback IPC without exposing the token to the WebView.
            // A new validated request makes the tray visible; no action is taken
            // unless the user explicitly clicks a decision in the local UI.
            let approval_handle=app.handle().clone();
            let approval_dir=app.path().app_config_dir()?;
            let approval_pending = Arc::new(AtomicBool::new(false));
            let watcher_pending = Arc::clone(&approval_pending);
            std::thread::spawn(move || {
                let mut seen=HashSet::<String>::new();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    let Some(window)=approval_handle.get_webview_window("tray") else {break;};
                    let current: HashSet<String> = match local_agent::request(&approval_dir, "approval_list", json!({})) {
                        Ok(reply) => reply["pending"].as_array().map(|pending| {
                            pending.iter().filter_map(|item| item["request_id"].as_str().map(str::to_owned)).collect()
                        }).unwrap_or_default(),
                        Err(_) => HashSet::new(),
                    };
                    watcher_pending.store(!current.is_empty(), Ordering::Relaxed);
                    if current.iter().any(|id| !seen.contains(id)) {
                        let _ = window.set_skip_taskbar(false);
                        if !window.is_visible().unwrap_or(false) {
                            let _ = window.center();
                        }
                        let _ = window.show();
                        let _ = window.set_focus();
                        let _ = window.request_user_attention(Some(UserAttentionType::Informational));
                        let _ = window.emit("approval-request", ());
                    } else if current.is_empty() && !seen.is_empty() {
                        let _ = window.request_user_attention(None);
                        let _ = window.set_skip_taskbar(true);
                    }
                    seen = current;
                }
            });
            let open = MenuItem::with_id(app, "open", "Open Desktop MCP", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Exit Desktop MCP", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;

            TrayIconBuilder::with_id("desktop-mcp")
                .icon(tray_icon())
                .tooltip("Desktop MCP")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|handle, event| {
                    if event.id() == "open" {
                        show_popup(handle, None);
                    } else if event.id() == "quit" {
                        handle.exit(0);
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        position,
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_popup(tray.app_handle(), Some(position));
                    }
                })
                .build(app)?;

            if let Some(window) = app.get_webview_window("tray") {
                let duplicate = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::Focused(false) = event {
                        // Windows may decline focus for a background popup.
                        // Keep the review visible while a request is pending.
                        if !show_on_launch && !approval_pending.load(Ordering::Relaxed) {
                            let _ = duplicate.hide();
                        }
                    }
                });
                if show_on_launch {
                    // Interactive smoke test without adding a dashboard or
                    // exposing any remote operations.
                    window.show()?;
                    window.set_focus()?;
                }
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Desktop MCP failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_release_versions_compare_numerically() {
        assert!(stable_version("v0.10.0") > stable_version("0.2.0"));
        assert_eq!(stable_version("v0.2.0"), stable_version("0.2.0"));
        for invalid in ["v01.2.3", "v1.2", "v1.2.3-rc.1", "v1.2.3.4", "v1.2.+3"] {
            assert_eq!(stable_version(invalid), None);
        }
    }

    #[test]
    fn initial_permissions_are_safe() {
        let s = Settings::default();
        assert!(!s.remote_access);
        assert!(!s.administrator_commands);
        assert_eq!(s.approval_mode, "ask");
        assert!(s.ask_destructive);
    }
}
