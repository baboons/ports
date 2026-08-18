//! The index page: what is bound, what is running, and one click between them.
//!
//! Served by the proxy itself rather than a second server, at the reserved
//! `ports.<tld>` and on any hostname nothing is bound to — the second is where
//! you land by accident, which is exactly when you want it.

use serde::{Deserialize, Serialize};

use crate::config::bindings::{check_domain, normalise_name, normalise_target, Bindings};
use crate::types::{PortRecord, Protocol};

/// The subdomain the index always answers on.
pub const INDEX_NAME: &str = "ports";

/// Is this hostname the index, under any configured domain?
///
/// `ports.<domain>` for every domain, so the page is reachable by the same
/// name however you got to the machine. The bare domain counts too — landing
/// on `devbox.lan` with nothing bound there should show the index, not an
/// error.
pub fn is_index_host(bindings: &Bindings, host: &str) -> bool {
    if bindings.is_bare_domain(host) {
        return true;
    }
    bindings
        .name_in(host)
        .is_some_and(|name| name == INDEX_NAME)
}

/// A row for the page: either something bound, or something merely running.
#[derive(Serialize)]
pub struct Row {
    pub port: u16,
    /// The bound hostname, when there is one.
    pub hostname: Option<String>,
    /// The name a bind would use, for the button to pre-fill.
    pub suggested: Option<String>,
    pub title: String,
    pub status: Option<u16>,
    pub protocol: String,
    pub project: Option<String>,
    pub framework: Option<String>,
    pub favicon: Option<String>,
    pub url: String,
    pub up: bool,
}

/// A domain the proxy answers for, and what it would take to reach it.
#[derive(Serialize)]
pub struct DomainRow {
    pub name: String,
    /// The first one: what new bindings are printed as.
    pub primary: bool,
    /// True when the OS resolves it without any help from us.
    pub automatic: bool,
    /// The hostname this page is reachable at under this domain.
    pub index_url: String,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub tld: String,
    pub http_port: u16,
    pub bound: Vec<Row>,
    pub unbound: Vec<Row>,
    pub domains: Vec<DomainRow>,
    /// False when the request came from another machine, where changing
    /// anything is refused; the page hides its controls to match.
    pub writable: bool,
}

/// What to show, given the bindings and the last scan.
pub fn snapshot(bindings: &Bindings, records: &[PortRecord], writable: bool) -> Snapshot {
    let by_port: std::collections::HashMap<u16, &PortRecord> =
        records.iter().map(|r| (r.port, r)).collect();

    // Links must carry the proxy's port unless it is the default one.
    let port_suffix = if bindings.http_port == 80 {
        String::new()
    } else {
        format!(":{}", bindings.http_port)
    };

    let mut bound = Vec::new();
    let mut bound_ports = std::collections::HashSet::new();

    for binding in &bindings.bindings {
        let port: u16 = binding
            .target
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        bound_ports.insert(port);

        let record = by_port.get(&port);
        let hostname = binding.hostname(bindings.primary());

        bound.push(Row {
            port,
            url: format!("http://{hostname}{port_suffix}/"),
            hostname: Some(hostname),
            suggested: None,
            title: record
                .map(|r| r.label().to_string())
                .unwrap_or_else(|| binding.name.clone()),
            status: record.and_then(|r| r.http.as_ref().map(|h| h.status)),
            protocol: record
                .map(|r| r.protocol.as_str().to_string())
                .unwrap_or_else(|| "http".into()),
            project: record.and_then(|r| r.process.as_ref()?.project_name.clone()),
            framework: record.and_then(|r| r.http.as_ref()?.framework.clone()),
            favicon: record.and_then(|r| r.meta.as_ref()?.favicon_hash.clone()),
            // Whether the record is alive is the scan's word; a binding to a
            // port nothing is on shows as down rather than vanishing.
            up: record.map(|r| r.alive).unwrap_or(false),
        });
    }

    let mut unbound: Vec<Row> = records
        .iter()
        .filter(|record| record.alive && record.protocol.is_web())
        .filter(|record| !bound_ports.contains(&record.port))
        // The proxy's own port would be a loop, and is not something to offer.
        .filter(|record| record.port != bindings.http_port)
        .filter(|record| bindings.https_port != Some(record.port))
        .map(|record| {
            let scheme = if record.protocol == Protocol::Https {
                "https"
            } else {
                "http"
            };
            Row {
                port: record.port,
                hostname: None,
                suggested: suggest_name(record),
                title: record.label().to_string(),
                status: record.http.as_ref().map(|h| h.status),
                protocol: record.protocol.as_str().to_string(),
                project: record.process.as_ref().and_then(|p| p.project_name.clone()),
                framework: record.http.as_ref().and_then(|h| h.framework.clone()),
                favicon: record.meta.as_ref().and_then(|m| m.favicon_hash.clone()),
                url: format!("{scheme}://127.0.0.1:{}/", record.port),
                up: true,
            }
        })
        .collect();

    unbound.sort_by_key(|r| r.port);
    bound.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    let needs_dns: std::collections::HashSet<&str> =
        bindings.domains_needing_dns().into_iter().collect();

    let domains = bindings
        .domains
        .iter()
        .enumerate()
        .map(|(index, name)| DomainRow {
            index_url: format!("http://{INDEX_NAME}.{name}{port_suffix}/"),
            automatic: !needs_dns.contains(name.as_str()),
            primary: index == 0,
            name: name.clone(),
        })
        .collect();

    Snapshot {
        tld: bindings.primary().to_string(),
        http_port: bindings.http_port,
        bound,
        unbound,
        domains,
        writable,
    }
}

/// The name `bind` would pick for this port, so the button can pre-fill it.
fn suggest_name(record: &PortRecord) -> Option<String> {
    use crate::cli::bind::slugify;
    record
        .process
        .as_ref()
        .and_then(|p| p.project_name.as_deref())
        .and_then(slugify)
        .or_else(|| record.meta.as_ref()?.title.as_deref().and_then(slugify))
}

#[derive(Deserialize)]
pub struct BindRequest {
    pub name: String,
    pub target: String,
}

#[derive(Deserialize)]
pub struct UnbindRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct DomainRequest {
    pub domain: String,
}

/// Apply a bind from the page, with the same rules the CLI uses.
pub fn apply_bind(bindings: &mut Bindings, request: &BindRequest) -> Result<String, String> {
    let Some(target) = normalise_target(&request.target) else {
        return Err(format!("'{}' is not a port or host:port", request.target));
    };

    let port: u16 = target.rsplit(':').next().unwrap_or("").parse().unwrap_or(0);
    if bindings.own_ports().contains(&port) {
        return Err(format!("port {port} is the proxy itself — that would loop"));
    }

    let Some(name) = normalise_name(&request.name, bindings.primary()) else {
        return Err(format!("'{}' is not a valid hostname label", request.name));
    };
    if name == INDEX_NAME {
        return Err(format!("'{INDEX_NAME}' is reserved for this page"));
    }

    bindings.upsert(name.clone(), target, crate::types::now_ms());
    Ok(format!("{name}.{}", bindings.primary()))
}

pub fn apply_unbind(bindings: &mut Bindings, request: &UnbindRequest) -> Result<String, String> {
    let Some(name) = normalise_name(&request.name, bindings.primary()) else {
        return Err(format!("'{}' is not a valid hostname label", request.name));
    };
    if !bindings.remove(&name) {
        return Err(format!("'{name}' is not bound"));
    }
    Ok(name)
}

/// Serve an extra domain, exactly as `ports domain --add` would.
pub fn apply_add_domain(
    bindings: &mut Bindings,
    request: &DomainRequest,
) -> Result<String, String> {
    let domain = check_domain(&request.domain)?;
    if bindings.domains.contains(&domain) {
        return Err(format!("{domain} is already served"));
    }
    bindings.domains.push(domain.clone());
    Ok(domain)
}

/// Stop serving a domain.
pub fn apply_remove_domain(
    bindings: &mut Bindings,
    request: &DomainRequest,
) -> Result<String, String> {
    let domain = request.domain.trim().trim_matches('.').to_lowercase();

    if !bindings.domains.contains(&domain) {
        return Err(format!("{domain} is not one of the domains served"));
    }
    // With none left the proxy would answer for nothing at all, including the
    // page you would be removing it from.
    if bindings.domains.len() == 1 {
        return Err(format!(
            "{domain} is the only domain — add another before removing it"
        ));
    }

    bindings.domains.retain(|d| *d != domain);
    Ok(domain)
}

/// Make a domain canonical, adding it if it is new.
pub fn apply_primary_domain(
    bindings: &mut Bindings,
    request: &DomainRequest,
) -> Result<String, String> {
    let domain = check_domain(&request.domain)?;
    // The others keep serving: changing which name is canonical should not
    // break links people already have.
    bindings.domains.retain(|d| *d != domain);
    bindings.domains.insert(0, domain.clone());
    Ok(domain)
}

/// Render the page.
///
/// `missing` names the hostname the visitor asked for, when they arrived here
/// by typing something that is not bound.
pub fn render(snapshot: &Snapshot, missing: Option<&str>) -> String {
    let data = serde_json::to_string(snapshot).unwrap_or_else(|_| "{}".into());

    let banner = match missing {
        Some(host) => format!(
            "<p class=miss>Nothing is bound to <code>{}</code>.</p>",
            escape(host)
        ),
        None => String::new(),
    };

    format!(
        r#"<!doctype html>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>ports</title>
<style>{CSS}</style>
<h1>ports <span class=tld>*.{tld}</span></h1>
{banner}
<div id=app></div>
<script>const DATA={data};{JS}</script>
"#,
        tld = escape(&snapshot.tld),
    )
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const CSS: &str = r#"
:root{--bg:#fff;--fg:#1a1a1a;--dim:#666;--line:#e6e6e6;--accent:#2563eb;
--ok:#15803d;--down:#b91c1c;--chip:#f3f4f6}
@media(prefers-color-scheme:dark){:root{--bg:#141414;--fg:#e8e8e8;--dim:#8b8b8b;
--line:#2a2a2a;--accent:#7aa2f7;--ok:#4ade80;--down:#f87171;--chip:#1f1f1f}}
*{box-sizing:border-box}
body{margin:0;padding:2.5rem 1.5rem 4rem;background:var(--bg);color:var(--fg);
font:14px/1.55 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
max-width:56rem;margin-inline:auto}
h1{font-size:1.1rem;font-weight:600;margin:0 0 1.5rem;letter-spacing:-.01em}
.tld{color:var(--dim);font-weight:400;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
h2{font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;
color:var(--dim);margin:2rem 0 .5rem}
.miss{background:var(--chip);border-radius:6px;padding:.6rem .9rem;margin:0 0 1.5rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.92em}
.row{display:flex;align-items:center;gap:.85rem;padding:.6rem .25rem;
border-bottom:1px solid var(--line)}
.row:last-child{border-bottom:0}
.icon{width:18px;height:18px;flex:0 0 18px;border-radius:3px;object-fit:contain}
.icon.blank{background:var(--chip)}
.main{flex:1;min-width:0}
.name{display:block;color:inherit;text-decoration:none;font-weight:500;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.name:hover{color:var(--accent);text-decoration:underline}
.sub{color:var(--dim);font-size:.82rem;white-space:nowrap;overflow:hidden;
text-overflow:ellipsis}
.meta{display:flex;align-items:center;gap:.5rem;flex:0 0 auto}
.chip{background:var(--chip);border-radius:4px;padding:.1rem .4rem;font-size:.75rem;
color:var(--dim);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.dom{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.add{display:flex;gap:.5rem;padding:.7rem .25rem}
.add input{flex:1;min-width:0;font:inherit;font-size:.85rem;padding:.3rem .6rem;
border-radius:5px;border:1px solid var(--line);background:transparent;color:var(--fg)}
.add input:focus{outline:none;border-color:var(--accent)}
.note{color:var(--dim);font-size:.82rem;padding:.2rem .25rem 0}
.up{color:var(--ok)}.down{color:var(--down)}
button{font:inherit;font-size:.8rem;padding:.25rem .7rem;border-radius:5px;
border:1px solid var(--line);background:transparent;color:var(--dim);cursor:pointer}
button:hover{border-color:var(--accent);color:var(--accent)}
button:disabled{opacity:.5;cursor:default}
.empty{color:var(--dim);padding:.6rem .25rem}
.err{color:var(--down);font-size:.82rem;padding:.4rem .25rem}
"#;

const JS: &str = r#"
const $=(h)=>{const d=document.createElement('div');d.innerHTML=h;return d.firstElementChild};
const esc=(s)=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function row(r, bound){
  const icon = r.favicon
    ? `<img class=icon src="/_ports/favicon/${esc(r.favicon)}" alt="">`
    : `<span class="icon blank"></span>`;
  const label = bound ? r.hostname : `localhost:${r.port}`;
  const bits = [r.project, r.framework, bound ? `:${r.port}` : null].filter(Boolean);
  const status = r.status ? `<span class=chip>${r.status}</span>` : '';
  const health = bound
    ? `<span class="${r.up?'up':'down'}">${r.up?'up':'down'}</span>` : '';
  const action = bound
    ? `<button data-unbind="${esc(r.hostname.replace('.'+DATA.tld,''))}">unbind</button>`
    : `<button data-bind="${r.port}" data-name="${esc(r.suggested||'')}">bind</button>`;

  return `<div class=row>${icon}
    <div class=main>
      <a class=name href="${esc(r.url)}" target=_blank rel=noreferrer>${esc(label)}</a>
      <span class=sub>${esc(r.title)}${bits.length?' · '+esc(bits.join(' · ')):''}</span>
    </div>
    <div class=meta>${status}${health}${action}</div>
  </div>`;
}

function domainRow(dm, d){
  const tag = dm.primary ? `<span class=chip>canonical</span>` : '';
  const setup = dm.automatic
    ? `<span class=chip>resolves itself</span>`
    : `<span class=chip>needs DNS</span>`;
  const actions = d.writable ? [
    dm.primary ? '' : `<button data-primary="${esc(dm.name)}">make canonical</button>`,
    d.domains.length > 1 ? `<button data-domrm="${esc(dm.name)}">remove</button>` : '',
  ].join('') : '';

  return `<div class=row>
    <span class="icon blank"></span>
    <div class=main>
      <a class="name dom" href="${esc(dm.index_url)}">*.${esc(dm.name)}</a>
    </div>
    <div class=meta>${tag}${setup}${actions}</div>
  </div>`;
}

function render(d){
  document.getElementById('app').innerHTML =
    `<h2>Domains</h2>` +
    d.domains.map(dm=>domainRow(dm,d)).join('') +
    (d.writable ? `<div class=add>
       <input id=newdomain placeholder="devbox.lan" autocomplete=off spellcheck=false>
       <button data-domadd>serve this too</button>
     </div>
     <div class=note>Point it at this machine in your DNS or hosts file, or run
       <code>sudo ports domain --install</code> to resolve it here.</div>`
     : `<div class=note>Read-only from another machine — change these on the box itself.</div>`) +
    `<h2>Bound</h2>` +
    (d.bound.length ? d.bound.map(r=>row(r,true)).join('')
                    : `<div class=empty>Nothing bound yet.</div>`) +
    `<h2>Running, not bound</h2>` +
    (d.unbound.length ? d.unbound.map(r=>row(r,false)).join('')
                      : `<div class=empty>Nothing else running.</div>`);
}

async function post(path, body, button){
  button.disabled = true;
  try{
    const res = await fetch(path, {
      method:'POST',
      // JSON forces a CORS preflight, which a page from another origin
      // cannot satisfy. Together with the server's Origin check that is
      // what stops any website from rebinding your domains.
      headers:{'content-type':'application/json'},
      body: JSON.stringify(body),
    });
    const out = await res.json();
    if(!res.ok) throw new Error(out.error || res.statusText);
    await refresh();
  }catch(err){
    const note = $(`<div class=err>${esc(err.message)}</div>`);
    button.closest('.row').after(note);
    setTimeout(()=>note.remove(), 6000);
    button.disabled = false;
  }
}

async function refresh(){
  const res = await fetch('/_ports/data');
  render(await res.json());
}

document.addEventListener('keydown', (event)=>{
  // Enter in the domain box should submit it, like any other one-field form.
  if(event.key === 'Enter' && event.target.id === 'newdomain'){
    document.querySelector('[data-domadd]')?.click();
  }
});

document.addEventListener('click', (event)=>{
  const domadd = event.target.closest('[data-domadd]');
  if(domadd){
    const input = document.getElementById('newdomain');
    const domain = input.value.trim();
    if(domain) post('/_ports/domain/add', {domain}, domadd);
    return;
  }
  const domrm = event.target.closest('[data-domrm]');
  if(domrm){ post('/_ports/domain/remove', {domain: domrm.dataset.domrm}, domrm); return; }
  const primary = event.target.closest('[data-primary]');
  if(primary){ post('/_ports/domain/primary', {domain: primary.dataset.primary}, primary); return; }

  const bind = event.target.closest('[data-bind]');
  if(bind){
    const suggested = bind.dataset.name || `app${bind.dataset.bind}`;
    const name = prompt('Bind as which name?', suggested);
    if(name) post('/_ports/bind', {name, target: bind.dataset.bind}, bind);
    return;
  }
  const unbind = event.target.closest('[data-unbind]');
  if(unbind) post('/_ports/unbind', {name: unbind.dataset.unbind}, unbind);
});

render(DATA);
// The daemon rescans every 20s; matching that keeps the page roughly current
// without polling for the sake of it.
setInterval(refresh, 20000);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DiscoveryTier, HttpInfo, PageMeta, ProcessInfo};

    fn web_record(port: u16, title: &str) -> PortRecord {
        let mut record = PortRecord::new(port, DiscoveryTier::Lsof, "127.0.0.1", 0);
        record.protocol = Protocol::Http;
        record.http = Some(HttpInfo {
            status: 200,
            ..Default::default()
        });
        record.meta = Some(PageMeta {
            title: Some(title.into()),
            ..Default::default()
        });
        record
    }

    #[test]
    fn recognises_the_index_under_every_configured_domain() {
        let bindings = Bindings {
            domains: vec!["localhost".into(), "devbox.lan".into()],
            ..Default::default()
        };

        assert!(is_index_host(&bindings, "ports.localhost"));
        assert!(is_index_host(&bindings, "ports.localhost:8080"));
        assert!(is_index_host(&bindings, "PORTS.LOCALHOST"));
        // The whole point of the list: the same name from the network too.
        assert!(is_index_host(&bindings, "ports.devbox.lan"));

        assert!(!is_index_host(&bindings, "myapp.localhost"));
        // A domain that is not configured is nothing to do with us.
        assert!(!is_index_host(&bindings, "ports.test"));
    }

    #[test]
    fn the_bare_domain_shows_the_index() {
        // Landing on http://devbox.lan/ with nothing bound there should show
        // what is available, not an error.
        let bindings = Bindings {
            domains: vec!["devbox.lan".into()],
            ..Default::default()
        };
        assert!(is_index_host(&bindings, "devbox.lan"));
        assert!(is_index_host(&bindings, "devbox.lan:8080"));
    }

    #[test]
    fn separates_what_is_bound_from_what_is_merely_running() {
        let mut bindings = Bindings::default();
        bindings.upsert("web".into(), "127.0.0.1:3000".into(), 0);

        let records = vec![web_record(3000, "Acme"), web_record(5173, "Vite")];
        let snap = snapshot(&bindings, &records, true);

        assert_eq!(snap.bound.len(), 1);
        assert_eq!(snap.bound[0].hostname.as_deref(), Some("web.localhost"));
        assert!(snap.bound[0].up);

        assert_eq!(snap.unbound.len(), 1);
        assert_eq!(snap.unbound[0].port, 5173);
    }

    #[test]
    fn a_binding_whose_server_stopped_shows_as_down_rather_than_vanishing() {
        let mut bindings = Bindings::default();
        bindings.upsert("gone".into(), "127.0.0.1:9999".into(), 0);

        let snap = snapshot(&bindings, &[], true);
        assert_eq!(snap.bound.len(), 1);
        assert!(!snap.bound[0].up);
    }

    #[test]
    fn the_proxys_own_ports_are_never_offered_for_binding() {
        let bindings = Bindings {
            http_port: 80,
            https_port: Some(443),
            ..Default::default()
        };
        let records = vec![web_record(80, "the proxy"), web_record(443, "the proxy")];

        let snap = snapshot(&bindings, &records, true);
        assert!(
            snap.unbound.is_empty(),
            "binding the proxy to itself would loop forever"
        );
    }

    #[test]
    fn suggests_a_name_from_the_project_then_the_title() {
        let mut record = web_record(3000, "Acme Dashboard");
        assert_eq!(suggest_name(&record).as_deref(), Some("acme-dashboard"));

        record.process = Some(ProcessInfo {
            pid: 1,
            project_name: Some("@acme/web".into()),
            ..Default::default()
        });
        // The project wins: it is what the repo is called.
        assert_eq!(suggest_name(&record).as_deref(), Some("web"));
    }

    #[test]
    fn binding_applies_the_same_rules_as_the_cli() {
        let mut bindings = Bindings::default();

        let ok = apply_bind(
            &mut bindings,
            &BindRequest {
                name: "myapp".into(),
                target: "4000".into(),
            },
        );
        assert_eq!(ok.as_deref(), Ok("myapp.localhost"));
        assert_eq!(bindings.get("myapp").unwrap().target, "127.0.0.1:4000");

        // A bare port is fine; nonsense is not.
        assert!(apply_bind(
            &mut bindings,
            &BindRequest {
                name: "x".into(),
                target: "not-a-port".into()
            }
        )
        .is_err());
        assert!(apply_bind(
            &mut bindings,
            &BindRequest {
                name: "has space".into(),
                target: "4000".into()
            }
        )
        .is_err());
    }

    #[test]
    fn the_index_name_cannot_be_bound_away() {
        let mut bindings = Bindings::default();
        let result = apply_bind(
            &mut bindings,
            &BindRequest {
                name: "ports".into(),
                target: "4000".into(),
            },
        );
        assert!(result.is_err(), "binding over the index would hide it");
    }

    #[test]
    fn binding_the_proxy_to_itself_is_refused() {
        let mut bindings = Bindings {
            http_port: 8080,
            ..Default::default()
        };
        let result = apply_bind(
            &mut bindings,
            &BindRequest {
                name: "loop".into(),
                target: "8080".into(),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn unbinding_reports_whether_anything_went() {
        let mut bindings = Bindings::default();
        bindings.upsert("myapp".into(), "127.0.0.1:4000".into(), 0);

        assert!(apply_unbind(
            &mut bindings,
            &UnbindRequest {
                name: "myapp".into()
            }
        )
        .is_ok());
        assert!(apply_unbind(
            &mut bindings,
            &UnbindRequest {
                name: "myapp".into()
            }
        )
        .is_err());
    }

    #[test]
    fn adding_a_domain_uses_the_same_rules_as_the_cli() {
        let mut bindings = Bindings::default();

        let added = apply_add_domain(
            &mut bindings,
            &DomainRequest {
                domain: "  DevBox.LAN ".into(),
            },
        );
        assert_eq!(added.as_deref(), Ok("devbox.lan"));
        assert!(bindings.domains.contains(&"devbox.lan".to_string()));

        // Same rejections the CLI gives, from the one shared check.
        assert!(apply_add_domain(
            &mut bindings,
            &DomainRequest {
                domain: "myapp.dev".into()
            }
        )
        .is_err());
        assert!(apply_add_domain(
            &mut bindings,
            &DomainRequest {
                domain: "has space".into()
            }
        )
        .is_err());
        // Twice is a no-op, not a duplicate.
        assert!(apply_add_domain(
            &mut bindings,
            &DomainRequest {
                domain: "devbox.lan".into()
            }
        )
        .is_err());
    }

    #[test]
    fn the_last_domain_cannot_be_removed() {
        // Removing it would leave the proxy answering for nothing at all —
        // including the page the button was on.
        let mut bindings = Bindings::default();
        let result = apply_remove_domain(
            &mut bindings,
            &DomainRequest {
                domain: "localhost".into(),
            },
        );
        assert!(result.is_err());
        assert_eq!(bindings.domains.len(), 1);
    }

    #[test]
    fn removing_a_domain_leaves_the_others_serving() {
        let mut bindings = Bindings {
            domains: vec!["localhost".into(), "devbox.lan".into()],
            ..Default::default()
        };
        bindings.upsert("myapp".into(), "127.0.0.1:4000".into(), 0);

        assert!(apply_remove_domain(
            &mut bindings,
            &DomainRequest {
                domain: "devbox.lan".into()
            }
        )
        .is_ok());

        assert!(bindings.resolve("myapp.localhost").is_some());
        assert!(bindings.resolve("myapp.devbox.lan").is_none());

        // Removing one that is not served says so rather than passing quietly.
        assert!(apply_remove_domain(
            &mut bindings,
            &DomainRequest {
                domain: "devbox.lan".into()
            }
        )
        .is_err());
    }

    #[test]
    fn making_a_domain_canonical_keeps_the_others() {
        let mut bindings = Bindings {
            domains: vec!["localhost".into(), "devbox.lan".into()],
            ..Default::default()
        };

        assert!(apply_primary_domain(
            &mut bindings,
            &DomainRequest {
                domain: "devbox.lan".into()
            }
        )
        .is_ok());

        assert_eq!(bindings.primary(), "devbox.lan");
        // The old canonical keeps serving; links people have should not break.
        assert!(bindings.domains.contains(&"localhost".to_string()));
        assert_eq!(bindings.domains.len(), 2);
    }

    #[test]
    fn a_domain_made_canonical_is_added_if_it_was_not_served() {
        let mut bindings = Bindings::default();
        assert!(apply_primary_domain(
            &mut bindings,
            &DomainRequest {
                domain: "devbox.lan".into()
            }
        )
        .is_ok());
        assert_eq!(bindings.primary(), "devbox.lan");
        assert_eq!(bindings.domains.len(), 2);
    }

    #[test]
    fn the_snapshot_says_which_domains_need_dns_setup() {
        let bindings = Bindings {
            domains: vec!["localhost".into(), "devbox.lan".into()],
            ..Default::default()
        };
        let snap = snapshot(&bindings, &[], true);

        let localhost = snap.domains.iter().find(|d| d.name == "localhost").unwrap();
        assert!(localhost.primary);
        assert!(localhost.automatic, "*.localhost resolves on its own");

        let lan = snap
            .domains
            .iter()
            .find(|d| d.name == "devbox.lan")
            .unwrap();
        assert!(!lan.primary);
        assert!(!lan.automatic, "a custom domain has to be pointed here");
    }

    #[test]
    fn a_read_only_snapshot_is_marked_as_such() {
        // The page hides its controls to match what the server would allow.
        let snap = snapshot(&Bindings::default(), &[], false);
        assert!(!snap.writable);
        assert!(snapshot(&Bindings::default(), &[], true).writable);
    }

    #[test]
    fn the_page_escapes_untrusted_hostnames() {
        let snap = snapshot(&Bindings::default(), &[], true);
        let html = render(&snap, Some("<script>alert(1)</script>.localhost"));
        assert!(!html.contains("<script>alert(1)"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn the_page_inlines_its_own_assets() {
        let mut bindings = Bindings::default();
        bindings.upsert("web".into(), "127.0.0.1:3000".into(), 0);
        let html = render(&snapshot(&bindings, &[], true), None);

        // Links to local servers are the point; loading assets from a CDN is
        // what would break this on a machine with no network.
        assert!(!html.contains("<script src"), "script should be inline");
        assert!(!html.contains("rel=stylesheet"), "styles should be inline");
        assert!(!html.contains("@import"));
    }
}
