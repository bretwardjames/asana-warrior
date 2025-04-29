import os
import re
import shutil
import sys
import webbrowser
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import click
import requests
from requests_oauthlib import OAuth2Session

from .config import load_config, save_config, get_config_path
import logging
import subprocess
import json

"""Asana ↔ Taskwarrior sync utility CLI."""
# Module-level logger
logger = logging.getLogger(__name__)
  
# -- Helpers ------------------------------------------------------------------
def _initialize(ctx, verbose_flag):
    """Load config, set up logging, Asana session, TaskWarrior, workspace maps, and current user gid."""
    # Configure logging if requested
    if verbose_flag or ctx.obj.get('verbose'):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('urllib3').setLevel(logging.DEBUG)
    # Load configuration
    config = load_config()
    if not config.get('auth_type'):
        click.echo("No configuration found. Please run `asana-warrior configure` first.")
        sys.exit(1)
    # Setup Asana session
    auth_type = config.get('auth_type')
    if auth_type == 'pat':
        token = config.get('asana_token')
        session = requests.Session()
        session.headers.update({'Authorization': f'Bearer {token}'})
    else:
        client_id = config.get('client_id')
        client_secret = config.get('client_secret')
        redirect_uri = config.get('redirect_uri')
        token = config.get('token')
        session = OAuth2Session(client_id, token=token, redirect_uri=redirect_uri)
    # Fetch user & workspaces
    me_resp = session.get('https://app.asana.com/api/1.0/users/me')
    if me_resp.status_code != 200:
        click.echo(f"Failed to fetch Asana user: {me_resp.status_code} {me_resp.text}")
        sys.exit(1)
    me_data = me_resp.json().get('data', {})
    ws_list = me_data.get('workspaces', [])
    ws_name_to_gid = {w.get('name'): w.get('gid') for w in ws_list}
    ws_gid_to_name = {v: k for k, v in ws_name_to_gid.items()}
    # Current user gid
    me_gid = me_data.get('gid')
    # Setup TaskWarrior interface
    from taskw import TaskWarrior
    tw = TaskWarrior()
    # Configured Asana project IDs for pull
    project_ids = config.get('projects', [])
    return config, session, tw, ws_name_to_gid, ws_gid_to_name, project_ids, me_gid


# Helper to parse various ISO8601 timestamps (Asana & Taskwarrior)
def iso_to_dt(ts):
    if not ts or not isinstance(ts, str):
        return None
    # Try Python 3.7+ fromisoformat with offset
    try:
        if ts.endswith('Z'):
            s = ts[:-1] + '+00:00'
            return datetime.fromisoformat(s)
        return datetime.fromisoformat(ts)
    except Exception:
        pass
    # Fallback: Taskwarrior format YYYYMMDDTHHMMSSZ
    try:
        if ts.endswith('Z') and 'T' in ts and len(ts.split('T')[0]) == 8:
            dt = datetime.strptime(ts, '%Y%m%dT%H%M%SZ')
            return dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None

# -- Annotation Sync Helper --------------------------------------------------
def _sync_annotations_for_task(session, tw, task, me_gid):
    """Import Asana comments into TW annotations and push new TW annotations to Asana for one task."""
    tw_uuid = task.get('uuid')
    asana_gid = task.get('asana_id')
    if not asana_gid:
        return
    # Import Asana comments → TW annotations
    # Gather already-imported GIDs and local texts
    imported = set()
    existing = []
    for ann in task.get('annotations', []):
        desc = ann.get('description', '') or ''
        m = re.search(r'\[[^:]+:(\d+)', desc)
        if m:
            imported.add(m.group(1))
        else:
            existing.append(desc.strip())
    # Fetch Asana stories
    try:
        resp = session.get(
            f'https://app.asana.com/api/1.0/tasks/{asana_gid}/stories',
            params={'opt_fields': 'gid,type,text,created_by.gid,created_by.name,created_at'}
        )
    except Exception:
        resp = None
    if not resp or resp.status_code != 200:
        return
    for story in resp.json().get('data', []):
        if story.get('type') != 'comment':
            continue
        s_gid = story.get('gid')
        text = story.get('text', '').strip()
        if not text or s_gid in imported or text in existing:
            continue
        author = story.get('created_by', {}) or {}
        display = 'me' if author.get('gid') == me_gid else author.get('name', '')
        created = story.get('created_at', '')
        note = f'[{display}:{s_gid} @ {created}] {text}'
        try:
            tw.task_annotate(task, note)
        except Exception:
            continue
    # Push new TW annotations → Asana comments
    # Refresh task annotations
    try:
        tdata = tw.filter_tasks({'uuid': tw_uuid})
        task2 = tdata[0]
    except Exception:
        return
    # Fetch existing Asana comment texts
    try:
        resp2 = session.get(
            f'https://app.asana.com/api/1.0/tasks/{asana_gid}/stories',
            params={'opt_fields': 'type,text'}
        )
        stories = resp2.json().get('data', []) if resp2.status_code == 200 else []
    except Exception:
        stories = []
    existing_texts = {s.get('text','') for s in stories if s.get('type') == 'comment'}
    # Export annotations once before loop
    try:
        raw = subprocess.check_output(['task', 'rc.hooks=off', f'uuid:{tw_uuid}', 'export'])
        arr = json.loads(raw)
        exported_annots = {a.get('description', '').strip() for a in arr[0].get('annotations', [])}
    except Exception:
        exported_annots = set()

    for ann in task2.get('annotations', []):
        desc = ann.get('description', '').strip()
        # Skip markers or empty
        if re.match(r'^\[[^:]+:\d+ @ .*?\]', desc) or not desc or desc in existing_texts:
            continue

        # Post to Asana
        try:
            post = session.post(
                f'https://app.asana.com/api/1.0/tasks/{asana_gid}/stories',
                json={'data': {'text': desc}}
            )
        except Exception:
            continue
        if post.status_code >= 400:
            continue

        nd = post.json().get('data', {})
        new_gid = nd.get('gid')
        created = nd.get('created_at', '')
        marker = f'[me:{new_gid} @ {created}] {desc}'

        # Denotate original
        if desc in exported_annots:
            try:
                tw._execute(tw_uuid, 'denotate', desc)
            except Exception:
                pass

        # Add marker
        try:
            tw.task_annotate(task, marker)
        except Exception:
            pass


@click.group()
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose debug output')
@click.pass_context
def cli(ctx, verbose):
    """Asana ↔ Taskwarrior sync utility."""
    # Check environment override for verbosity
    envv = os.environ.get('ASANA_WARRIOR_VERBOSE', '')
    if envv.lower() in ('1', 'true', 'yes'):
        verbose = True
    # Configure logging
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    # Enable verbose HTTP logging
    if verbose:
        logging.getLogger('urllib3').setLevel(logging.DEBUG)
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose

@cli.command()
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose debug output')
@click.pass_context
def configure(ctx, verbose):
    """Configure Asana authentication and workspace."""
    # If verbose for this command, increase logging
    if verbose or ctx.obj.get('verbose'):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('urllib3').setLevel(logging.DEBUG)
    logger.debug("configure command called")
    global token, oauth
    config = load_config()
    # Load .env for default credentials
    env_vars = {}
    if os.path.exists('.env'):
        with open('.env') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                v = v.strip().strip('"').strip("'")
                env_vars[k] = v
    method = click.prompt(
        "Authentication method",
        type=click.Choice(["oauth", "pat"], case_sensitive=False),
        default="pat",
    ).lower()
    if method == "pat":
        # PAT can come from .env or prompt
        if 'ASANA_PAT' in env_vars:
            use_env = click.confirm("Found ASANA_PAT in .env. Use it?", default=True)
            if use_env:
                token = env_vars['ASANA_PAT']
            else:
                token = click.prompt("Asana Personal Access Token", hide_input=True)
        else:
            token = click.prompt("Asana Personal Access Token", hide_input=True)
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(
            "https://app.asana.com/api/1.0/users/me", headers=headers
        )
        if resp.status_code != 200:
            click.echo(f"Authentication failed: {resp.status_code} {resp.text}")
            sys.exit(1)
        me = resp.json().get("data", {})
        config["auth_type"] = "pat"
        config["asana_token"] = token
    else:
        # OAuth credentials can come from .env or prompt
        if 'ASANA_CLIENT_ID' in env_vars and 'ASANA_CLIENT_SECRET' in env_vars:
            use_env = click.confirm(
                "Found ASANA_CLIENT_ID and ASANA_CLIENT_SECRET in .env. Use them?", default=True
            )
            if use_env:
                client_id = env_vars['ASANA_CLIENT_ID']
                client_secret = env_vars['ASANA_CLIENT_SECRET']
            else:
                client_id = click.prompt("Asana OAuth Client ID")
                client_secret = click.prompt(
                    "Asana OAuth Client Secret", hide_input=True
                )
        else:
            client_id = click.prompt("Asana OAuth Client ID")
            client_secret = click.prompt(
                "Asana OAuth Client Secret", hide_input=True
            )
        # Redirect URI default from .env or fallback
        default_redirect = env_vars.get('ASANA_REDIRECT_URI', 'urn:ietf:wg:oauth:2.0:oob')
        redirect_uri = click.prompt(
            "Redirect URI (as registered)", default=default_redirect
        )
        oauth = OAuth2Session(client_id, redirect_uri=redirect_uri)
        auth_url, _ = oauth.authorization_url(
            "https://app.asana.com/-/oauth_authorize"
        )
        click.echo("Opening browser to authenticate with Asana...")
        webbrowser.open(auth_url)
        click.echo(f"If the browser did not open, visit:\n{auth_url}")

        code_container = {}
        class OAuthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                params = parse_qs(urlparse(self.path).query)
                if "code" in params:
                    code_container["code"] = params["code"][0]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>Authorization successful.</h1>"
                        b"You may close this window.</body></html>"
                    )
                else:
                    self.send_response(400)
                    self.end_headers()

        port = urlparse(redirect_uri).port or 80
        httpd = HTTPServer(("localhost", port), OAuthHandler)
        click.echo(f"Waiting for OAuth callback on {redirect_uri} ...")
        httpd.handle_request()
        code = code_container.get("code")
        if not code:
            click.echo("Authorization code not received. Aborting.")
            return

        token_data = oauth.fetch_token(
            "https://app.asana.com/-/oauth_token",
            client_secret=client_secret,
            code=code,
        )
        resp = oauth.get("https://app.asana.com/api/1.0/users/me")
        if resp.status_code != 200:
            click.echo(f"Authentication failed: {resp.status_code} {resp.text}")
            sys.exit(1)
        me = resp.json().get("data", {})
        config.update(
            {
                "auth_type": "oauth",
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "token": token_data,
            }
        )

    # Workspace selection
    workspaces = me.get("workspaces", [])
    if not workspaces:
        click.echo("No workspaces found in your Asana account.")
        return
    click.echo("Available workspaces:")
    for idx, ws in enumerate(workspaces, 1):
        click.echo(f"{idx}. {ws['name']}")
    click.echo("0. All workspaces")
    choice = click.prompt("Select workspace (number)", type=int, default=1)
    if choice == 0:
        selected = [ws["gid"] for ws in workspaces]
    elif 1 <= choice <= len(workspaces):
        selected = [workspaces[choice - 1]["gid"]]
    else:
        click.echo("Invalid choice.")
        return
    config["workspaces"] = selected

    # Project selection for chosen workspaces
    if method == "pat":
        session = requests.Session()
        session.headers.update({"Authorization": f"Bearer {token}"})
    else:
        session = oauth

    project_ids = []
    for ws_id in selected:
        ws_obj = next((w for w in workspaces if w["gid"] == ws_id), None)
        ws_name = ws_obj.get("name") if ws_obj else ws_id
        click.echo(f"Workspace '{ws_name}' projects:")
        resp = session.get(
            f"https://app.asana.com/api/1.0/projects?workspace={ws_id}&archived=false"
        )
        if resp.status_code != 200:
            click.echo(f"  Failed to fetch projects: {resp.status_code} {resp.text}")
            continue
        projects = resp.json().get("data", [])
        if not projects:
            click.echo("  (no projects found)")
            continue
        click.echo("  0. All projects")
        for idx, proj in enumerate(projects, start=1):
            click.echo(f"  {idx}. {proj['name']}")
        selection = click.prompt(
            "Select projects to sync (comma-separated indices, 0=all)", default="0"
        )
        if selection.strip() == "0":
            project_ids.extend(p["gid"] for p in projects)
        else:
            for part in selection.split(","):
                part = part.strip()
                if not part:
                    continue
                try:
                    num = int(part)
                except ValueError:
                    click.echo(f"  Ignoring invalid input: {part}")
                    continue
                if num == 0:
                    project_ids.extend(p["gid"] for p in projects)
                elif 1 <= num <= len(projects):
                    project_ids.append(projects[num - 1]["gid"])
                else:
                    click.echo(f"  Ignoring invalid project selection: {num}")
    # Deduplicate project IDs
    project_ids = list(dict.fromkeys(project_ids))
    config["projects"] = project_ids

    save_config(config)
    run_sync = click.confirm(f"Configuration saved to {get_config_path()}. Sync now?", default=True)
    if run_sync:
        ctx = click.get_current_context()
        ctx.invoke(sync)

def sync_one(task_id):
    """Bidirectional sync between Asana and Taskwarrior for a single task."""
    # Perform push (TW -> Asana) for this task
    ctx = click.get_current_context()
    click.echo(f"Syncing TaskWarrior task {task_id} via push and pull")
    ctx.invoke(push, task_id=task_id)
    # Reload TaskWarrior to get updated Asana ID
    from taskw import TaskWarrior
    tw = TaskWarrior()
    tw_tasks = tw.filter_tasks({'uuid': task_id})
    if not tw_tasks:
        click.echo(f"No TaskWarrior task with uuid {task_id} found.")
        return
    asana_id = tw_tasks[0].get('asana_id')
    if not asana_id:
        click.echo(f"Task {task_id} has no Asana ID after push; skipping pull.")
        return
    # Perform pull (Asana -> TW) for this Asana ID
    ctx.invoke(pull, task_id=asana_id)
    # Sync annotations for this task
    # Re-initialize session and TaskWarrior to get context
    config, session, tw2, _, _, _, me_gid = _initialize(ctx, ctx.obj.get('verbose', False))
    try:
        task2 = tw2.filter_tasks({'uuid': task_id})[0]
        _sync_annotations_for_task(session, tw2, task2, me_gid)
    except Exception:
        pass

@cli.command()
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose debug output')
@click.option('-t', '--task-id', is_flag=False, type=str, help='Send a single task id to sync that task only.')
@click.pass_context
def push(ctx, verbose, task_id=None):
    """Push tasks from Taskwarrior to Asana. Optional `task_id` to push one task only."""
    # Initialize Asana session and TaskWarrior
    config, session, tw, ws_name_to_gid, ws_gid_to_name, project_ids, me_gid = _initialize(ctx, verbose)
    # Determine tasks to export (only tasks without existing Asana ID)
    if task_id:
        tw_tasks = tw.filter_tasks({'uuid': task_id})
        if not tw_tasks:
            click.echo(f"No TaskWarrior task with uuid {task_id}")
            return
        task = tw_tasks[0]
        # If already pushed to Asana, merge completion last-write-wins
        if task.get('asana_id'):
            asana_gid = task['asana_id']
            # Fetch Asana completion and modified timestamp
            try:
                resp0 = session.get(
                    f'https://app.asana.com/api/1.0/tasks/{asana_gid}',
                    params={'opt_fields': 'completed,modified_at'}
                )
                data0 = resp0.json().get('data', {}) if resp0.status_code == 200 else {}
            except Exception:
                data0 = {}
            asana_mod_ts = data0.get('modified_at', '')
            asana_mod_dt = iso_to_dt(asana_mod_ts) or datetime.fromtimestamp(0, timezone.utc)
            completed_asana = data0.get('completed', False)
            # Get TW completion and modified
            completed_tw = (task.get('status') == 'completed')
            tw_mod_ts = task.get('modified', '')
            tw_mod_dt = iso_to_dt(tw_mod_ts) or datetime.fromtimestamp(0, timezone.utc)
            # If status differs, apply the more recent change
            if completed_tw != completed_asana:
                if asana_mod_dt > tw_mod_dt:
                    # Asana change more recent → apply to TW
                    if completed_asana:
                        tw.task_done(uuid=task_id)
                    else:
                        tw._execute(task_id, 'modify', 'status:pending')
                    # Update sync timestamp
                    tw._execute(task_id, 'modify', f'asana_modified_at:{asana_mod_ts}')
                    click.echo(f"  Synced completion Asana→TW for task {task_id}")
                    return
                else:
                    # TW change more recent → push to Asana
                    click.echo(f"  Synced completion TW→Asana for task {task_id}")
                    upayload = {'data': {'completed': completed_tw}}
                    try:
                        cresp = session.put(
                            f'https://app.asana.com/api/1.0/tasks/{asana_gid}',
                            json=upayload
                        )
                        cresp.raise_for_status()
                        new_mod = cresp.json().get('data', {}).get('modified_at', '')
                        tw._execute(task_id, 'modify', f'asana_modified_at:{new_mod}')
                    except Exception as e:
                        click.echo(f"  Error syncing completion to Asana {asana_gid}: {e}")
                    return
            # Otherwise no completion diff → proceed to export other fields
            click.echo(f"Updating Asana task {asana_gid} from TW {task_id}...")
            # Build update payload for name/notes/due/custom_fields
            desc = task.get('description', '')
            if '\n\n' in desc:
                name, notes = desc.split('\n\n', 1)
            else:
                name, notes = desc, ''
            upayload = {'data': {'name': name, 'notes': notes}}
            # Handle due date
            due_val = task.get('due')
            if due_val:
                if re.match(r'^\d{4}-\d{2}-\d{2}$', due_val):
                    upayload['data']['due_on'] = due_val
                else:
                    dt_due = iso_to_dt(due_val)
                    if dt_due:
                        upayload['data']['due_on'] = dt_due.date().isoformat()
            # Map additional fields
            for twk, ak in config.get('field_mappings', {}).get('tw_to_asana', {}).items():
                if task.get(twk) is not None:
                    if ak.startswith('custom_field.'):
                        _, cf_gid = ak.split('.', 1)
                        upayload['data'].setdefault('custom_fields', {})[cf_gid] = task[twk]
                    else:
                        upayload['data'][ak] = task[twk]
            # Ensure we include current completion too
            upayload['data']['completed'] = completed_tw
            # Send update to Asana
            try:
                uresp = session.put(f'https://app.asana.com/api/1.0/tasks/{asana_gid}', json=upayload)
                uresp.raise_for_status()
                udata = uresp.json().get('data', {})
                new_mod = udata.get('modified_at', '')
                tw._execute(task_id, 'modify', f'asana_modified_at:{new_mod}')
                click.echo(f"  Updated Asana task {asana_gid}")
            except Exception as e:
                click.echo(f"  Failed updating Asana task {asana_gid}: {e}")
            return
        # End existing Asana merge, now treat as new task
        export_tasks = [task]
    else:
        # All tasks without an Asana ID
        data = tw.load_tasks('all')
        export_tasks = []
        for lst in data.values():
            for task in lst:
                if not task.get('asana_id'):
                    export_tasks.append(task)
    click.echo("Exporting TaskWarrior tasks to Asana...")
    # Process each task
    for task in export_tasks:
        tw_uuid = task.get('uuid')
        proj_full = task.get('project', '')
        if not proj_full or '.' not in proj_full:
            click.echo(f"  Skipping TW {tw_uuid}: invalid project format")
            continue
        ws_name, proj_name = proj_full.split('.', 1)
        ws_id = ws_name_to_gid.get(ws_name)
        if not ws_id:
            click.echo(f"  Unknown workspace '{ws_name}' for task {tw_uuid}")
            continue
        # Ensure Asana project exists
        resp_pl = session.get(f'https://app.asana.com/api/1.0/projects?workspace={ws_id}&archived=false')
        if resp_pl.status_code != 200:
            click.echo(f"  Failed to list Asana projects for workspace '{ws_name}'")
            continue
        proj_map = {p['name']: p['gid'] for p in resp_pl.json().get('data', [])}
        if proj_name in proj_map:
            target_gid = proj_map[proj_name]
        else:
            payload = {'data': {'workspace': ws_id, 'name': proj_name}}
            cresp = session.post('https://app.asana.com/api/1.0/projects', json=payload)
            if cresp.status_code >= 400:
                click.echo(f"  Failed to create Asana project '{proj_name}': {cresp.status_code}")
                continue
            target_gid = cresp.json().get('data', {}).get('gid')
            click.echo(f"  Created Asana project '{proj_name}' (gid: {target_gid})")
            config.setdefault('projects', []).append(target_gid)
            save_config(config)
        # Build task payload
        desc = task.get('description', '')
        if '\n\n' in desc:
            name, notes = desc.split('\n\n', 1)
        else:
            name, notes = desc, ''
        tpayload = {'data': {'name': name, 'notes': notes, 'projects': [target_gid]}}
        due_val = task.get('due')
        if due_val:
            if re.match(r'^\d{4}-\d{2}-\d{2}$', due_val):
                tpayload['data']['due_on'] = due_val
            else:
                dt_due = iso_to_dt(due_val)
                if dt_due:
                    tpayload['data']['due_on'] = dt_due.date().isoformat()
        for twk, ak in config.get('field_mappings', {}).get('tw_to_asana', {}).items():
            if twk in task and task[twk] is not None:
                if ak.startswith('custom_field.'):
                    _, cf_gid = ak.split('.', 1)
                    tpayload['data'].setdefault('custom_fields', {})[cf_gid] = task[twk]
                else:
                    tpayload['data'][ak] = task[twk]
        # Create Asana task
        try:
            tresp = session.post('https://app.asana.com/api/1.0/tasks', json=tpayload)
        except Exception as e:
            click.echo(f"  Error creating Asana task for TW {tw_uuid}: {e}")
            continue
        if tresp.status_code >= 400:
            click.echo(f"  Failed to create Asana task for TW {tw_uuid}: {tresp.status_code}")
            continue
        data = tresp.json().get('data', {})
        new_gid = data.get('gid')
        new_mod = data.get('modified_at', '')
        try:
            tw._execute(tw_uuid, 'modify', f'asana_id:{new_gid}', f'asana_modified_at:{new_mod}')
            click.echo(f"  Exported TW {tw_uuid} to Asana {new_gid}")
        except Exception as e:
            click.echo(f"  Failed updating TW {tw_uuid}: {e}")

@cli.command()
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose debug output')
@click.option('-t', '--task-id', is_flag=False, type=str, help='Send a single task id to sync that task only.')
@click.pass_context
def pull(ctx, verbose, task_id=None):
    """Pull tasks from Asana to Taskwarrior. Optional `task_id` to pull one task only."""
    # Initialize Asana session and TaskWarrior
    config, session, tw, ws_name_to_gid, ws_gid_to_name, project_ids, me_gid = _initialize(ctx, verbose)
    # Determine Asana->TW field mappings
    base_fields = {'name', 'notes', 'due_on'}
    for ak in config.get('field_mappings', {}).get('asana_to_tw', {}):
        if ak.startswith('custom_field.'):
            base_fields.add('custom_fields')
        else:
            base_fields.add(ak)
    opt_fields = ','.join(sorted(base_fields))
    # Single task pull
    if task_id:
        # Skip if already imported into TaskWarrior
        existing = tw.filter_tasks({'asana_id': task_id})
        if existing:
            click.echo(f"TaskWarrior already contains Asana task {task_id}; skipping pull.")
            return
        # Fetch single task details
        tgid = task_id
        resp_t = session.get(f'https://app.asana.com/api/1.0/tasks/{tgid}', params={'opt_fields': opt_fields})
        if resp_t.status_code != 200:
            click.echo(f"Failed to fetch Asana task {tgid}: {resp_t.status_code}")
            return
        td = resp_t.json().get('data', {})
        # Build TW kwargs
        desc = td.get('name', '')
        notes = td.get('notes', '')
        if notes:
            desc = f"{desc}\n\n{notes}"
        due = td.get('due_on')
        # Derive TW project from configured project list
        tw_project = None
        if 'projects' in td and td['projects']:
            pr = td['projects'][0]
            ws = pr.get('workspace', {}).get('name')
            pn = pr.get('name')
            if ws and pn:
                tw_project = f"{ws}.{pn}"
        if not tw_project and project_ids:
            # fallback to first configured project
            proj_info = session.get(f'https://app.asana.com/api/1.0/projects/{project_ids[0]}', params={'opt_fields':'name,workspace.name'})
            if proj_info.status_code == 200:
                pd = proj_info.json().get('data', {})
                tw_project = f"{pd.get('workspace',{}).get('name')}.{pd.get('name')}"
        kwargs = {'description': desc, 'project': tw_project, 'asana_id': tgid}
        for ak, twk in config.get('field_mappings', {}).get('asana_to_tw', {}).items():
            if ak.startswith('custom_field.'):
                cf_gid = ak.split('.',1)[1]
                cfval = td.get('custom_fields', {}).get(cf_gid)
            else:
                cfval = td.get(ak)
                if isinstance(cfval, dict) and 'name' in cfval:
                    cfval = cfval.get('name')
            if cfval is not None:
                kwargs[twk] = cfval
        if due:
            kwargs['due'] = due
        try:
            tw.task_add(**kwargs)
            click.echo(f"Added Asana {tgid} to TW: {kwargs.get('description','')}")
        except Exception as e:
            click.echo(f"Error adding task {tgid}: {e}")
        return
    # Bulk import for each configured project
    for proj_gid in project_ids:
        resp_proj = session.get(f'https://app.asana.com/api/1.0/projects/{proj_gid}', params={'opt_fields':'name,workspace.name'})
        if resp_proj.status_code != 200:
            click.echo(f"Failed to fetch project {proj_gid}: {resp_proj.status_code}")
            continue
        proj = resp_proj.json().get('data', {})
        proj_name = proj.get('name')
        ws_name = proj.get('workspace', {}).get('name')
        tw_project = f"{ws_name}.{proj_name}"
        click.echo(f"Importing tasks for project {tw_project}...")
        resp_tasks = session.get(f'https://app.asana.com/api/1.0/projects/{proj_gid}/tasks')
        if resp_tasks.status_code != 200:
            click.echo(f"  Failed to list tasks for project {proj_name}: {resp_tasks.status_code}")
            continue
        tasks = resp_tasks.json().get('data', [])
        for t in tasks:
            t_gid = t.get('gid')
            if tw.filter_tasks({'asana_id': t_gid}):
                continue
            resp_t = session.get(f'https://app.asana.com/api/1.0/tasks/{t_gid}', params={'opt_fields': opt_fields})
            if resp_t.status_code != 200:
                click.echo(f"  Failed to fetch task {t_gid}: {resp_t.status_code}")
                continue
            td = resp_t.json().get('data', {})
            desc = td.get('name','')
            notes = td.get('notes','')
            if notes:
                desc = f"{desc}\n\n{notes}"
            due = td.get('due_on')
            kwargs = {'description': desc, 'project': tw_project, 'asana_id': t_gid}
            for ak, twk in config.get('field_mappings', {}).get('asana_to_tw', {}).items():
                if ak.startswith('custom_field.'):
                    cf_gid = ak.split('.',1)[1]
                    cfval = td.get('custom_fields', {}).get(cf_gid)
                else:
                    cfval = td.get(ak)
                    if isinstance(cfval, dict) and 'name' in cfval:
                        cfval = cfval.get('name')
                if cfval is not None:
                    kwargs[twk] = cfval
            if due:
                kwargs['due'] = due
            try:
                tw.task_add(**kwargs)
                click.echo(f"  Added task: {desc}")
            except Exception as e:
                click.echo(f"  Error adding task {t_gid}: {e}")

@cli.command()
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose debug output')
@click.option('-t', '--task-id', is_flag=False, type=str, help='Send a single task id to sync that task only.')
@click.pass_context
def sync(ctx, verbose, task_id=None):
    """Bidirectional sync between Asana and Taskwarrior."""
    # Delegate sync to push/pull/sync_one workflows
    # Initialize sessions and interfaces
    config, session, tw, ws_name_to_gid, ws_gid_to_name, project_ids, me_gid = _initialize(ctx, verbose)
    # Single-task sync
    if task_id:
        click.echo(f"Syncing single TaskWarrior task {task_id}...")
        sync_one(task_id)
        return
    # Bulk sync: merge existing tasks
    data = tw.load_tasks('all')
    for lst in data.values():
        for task in lst:
            if task.get('asana_id'):
                sync_one(task.get('uuid'))
    # Push new TaskWarrior tasks to Asana
    ctx.invoke(push)
    # Pull new Asana tasks to TaskWarrior
    ctx.invoke(pull)
    return
    # If verbose from this command or global, enable detailed logging
    if verbose or ctx.obj.get('verbose'):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('urllib3').setLevel(logging.DEBUG)
    logger.debug("sync command called")
    global payload
    config = load_config()
    if not config.get("auth_type"):
        click.echo("No configuration found. Please run `asana-warrior configure` first.")
        return
    auth_type = config.get("auth_type")
    # Setup Asana session
    if auth_type == "pat":
        token = config.get("asana_token")
        session = requests.Session()
        session.headers.update({"Authorization": f"Bearer {token}"})
    else:
        client_id = config.get("client_id")
        client_secret = config.get("client_secret")
        redirect_uri = config.get("redirect_uri")
        token = config.get("token")
        session = OAuth2Session(client_id, token=token, redirect_uri=redirect_uri)
    # Build workspace name<->gid maps for export/import logic
    me_resp = session.get("https://app.asana.com/api/1.0/users/me")
    if me_resp.status_code != 200:
        click.echo(f"Failed to fetch user workspaces: {me_resp.status_code} {me_resp.text}")
        return
    me_data = me_resp.json().get("data", {})
    # Current user gid for skipping self-posted comments
    me_gid = me_data.get("gid")
    ws_list = me_data.get("workspaces", [])
    ws_name_to_gid = {w.get("name"): w.get("gid") for w in ws_list}
    ws_gid_to_name = {v: k for k, v in ws_name_to_gid.items()}
    if task_id:
        click.echo(f'Syncing single task id {task_id}')
    # Setup TaskWarrior
    # Initialize TaskWarrior interface
    from taskw import TaskWarrior
    tw = TaskWarrior()
    # Projects to sync
    project_ids = config.get("projects", [])
    if not project_ids:
        click.echo("No projects configured to sync.")
        return
    # Iterate through each configured Asana project
    for proj_gid in project_ids:
        # Fetch project metadata for naming
        resp_proj = session.get(
            f"https://app.asana.com/api/1.0/projects/{proj_gid}",
            params={"opt_fields": "name,workspace.name"},
        )
        if resp_proj.status_code != 200:
            click.echo(f"Failed to fetch project {proj_gid}: {resp_proj.status_code}")
            continue
        proj = resp_proj.json().get("data", {})
        proj_name = proj.get("name")
        ws_name = proj.get("workspace", {}).get("name")
        tw_project = f"{ws_name}.{proj_name}"
        click.echo(f"Importing tasks for project {tw_project}...")
        # List tasks in project
        resp_tasks = session.get(
            f"https://app.asana.com/api/1.0/projects/{proj_gid}/tasks"
        )
        if resp_tasks.status_code != 200:
            click.echo(f"  Failed to list tasks for project {proj_name}: {resp_tasks.status_code}")
            continue
        tasks = resp_tasks.json().get("data", [])
        for t in tasks:
            t_gid = t.get("gid")
            # Skip if already imported
            existing = tw.filter_tasks({"asana_id": t_gid})
            if existing:
                continue
            # Fetch full task details, including any mapped fields
            fields = {"name", "notes", "due_on"}
            for ak in config.get('field_mappings', {}).get('asana_to_tw', {}):
                if ak.startswith('custom_field.'):
                    fields.add('custom_fields')
                else:
                    fields.add(ak)
            opt_fields = ",".join(sorted(fields))
            resp_t = session.get(
                f"https://app.asana.com/api/1.0/tasks/{t_gid}",
                params={"opt_fields": opt_fields},
            )
            if resp_t.status_code != 200:
                click.echo(f"  Failed to fetch task {t_gid}: {resp_t.status_code}")
                continue
            logger.debug("Asana task fetch response: %s", resp_t.text)
            td = resp_t.json().get("data", {})
            desc = td.get("name", "")
            notes = td.get("notes", "")
            if notes:
                desc = f"{desc}\n\n{notes}"
            due = td.get("due_on")
            # Build TaskWarrior add kwargs
            kwargs = {"description": desc, "project": tw_project, "asana_id": t_gid}
            for ak, twk in config.get('field_mappings', {}).get('asana_to_tw', {}).items():
                # support built-in and custom fields
                if ak.startswith('custom_field.'):
                    cf_gid = ak.split('.',1)[1]
                    cfval = td.get('custom_fields',{}).get(cf_gid)
                else:
                    cfval = td.get(ak)
                    # If Asana returns an object (e.g. assignee), extract its name
                    if isinstance(cfval, dict) and 'name' in cfval:
                        cfval = cfval.get('name')
                if cfval is not None:
                    kwargs[twk] = cfval
            if due:
                kwargs["due"] = due
            try:
                tw.task_add(**kwargs)
                click.echo(f"  Added task: {desc}")
            except Exception as e:
                click.echo(f"  Error adding task {t_gid}: {e}")
    # Export new TaskWarrior tasks to Asana
    click.echo("Exporting new TaskWarrior tasks to Asana...")
    # Load all TW tasks
    export_data = tw.load_tasks('all')
    export_tasks = []
    for lst in export_data.values():
        export_tasks.extend(lst)
    for task in export_tasks:
        tw_uuid = task.get('uuid')
        if not tw_uuid:
            continue
        # Only export tasks without an Asana ID
        if task.get('asana_id'):
            continue
        proj_full = task.get('project', '')
        if not proj_full or '.' not in proj_full:
            continue
        ws_name, proj_name = proj_full.split('.', 1)
        ws_id = ws_name_to_gid.get(ws_name)
        if not ws_id:
            click.echo(f"  Unknown workspace '{ws_name}' for task {tw_uuid}, skipping export.")
            continue
        # Fetch or create Asana project
        resp_pl = session.get(
            f"https://app.asana.com/api/1.0/projects?workspace={ws_id}&archived=false"
        )
        if resp_pl.status_code != 200:
            click.echo(f"  Failed to list projects for workspace '{ws_name}': {resp_pl.status_code}")
            continue
        proj_list = resp_pl.json().get('data', [])
        proj_map = {p['name']: p['gid'] for p in proj_list}
        if proj_name in proj_map:
            target_gid = proj_map[proj_name]
        else:
            # Create new project
            cpayload = {'data': {'workspace': ws_id, 'name': proj_name}}
            cresp = session.post(
                "https://app.asana.com/api/1.0/projects",
                json=cpayload
            )
            if cresp.status_code >= 400:
                click.echo(f"  Failed to create project '{proj_name}': {cresp.status_code} {cresp.text}")
                continue
            new_proj = cresp.json().get('data', {})
            target_gid = new_proj.get('gid')
            click.echo(f"  Created Asana project '{proj_name}' (gid: {target_gid}) in workspace '{ws_name}'")
            # Add to config for import, and save
            config.setdefault('projects', []).append(target_gid)
            save_config(config)
        # Prepare task payload
        description = task.get('description', '')
        if '\n\n' in description:
            name, notes = description.split('\n\n', 1)
        else:
            name, notes = description, ''
        tpayload = {'data': {'name': name, 'notes': notes, 'projects': [target_gid]}}
        due_val = task.get('due')
        if due_val:
            if re.match(r'^\d{4}-\d{2}-\d{2}$', due_val):
                tpayload['data']['due_on'] = due_val
            else:
                dt_due = iso_to_dt(due_val)
                if dt_due:
                    tpayload['data']['due_on'] = dt_due.date().isoformat()
        for twk, ak in config.get('field_mappings', {}).get('tw_to_asana', {}).items():
            if twk in task and task[twk] is not None:
                # dotted path support for custom_field.<gid>
                if ak.startswith('custom_field.'):
                    _, cf_gid = ak.split('.',1)
                    tpayload['data'].setdefault('custom_fields', {})[cf_gid] = task[twk]
                else:
                    tpayload['data'][ak] = task[twk]
        # Create Asana task
        try:
            tresp = session.post(
                "https://app.asana.com/api/1.0/tasks",
                json=tpayload
            )
        except Exception as e:
            click.echo(f"  Connection error creating Asana task for TW {tw_uuid}: {e}")
            continue
        if tresp.status_code >= 400:
            click.echo(f"  Failed to create Asana task for TW {tw_uuid}: {tresp.status_code} {tresp.text}")
            click.echo(f"    Payload: {tpayload}")
            continue
        tdata = tresp.json().get('data', {})
        new_gid = tdata.get('gid')
        new_mod = tdata.get('modified_at', '')
        # Update TW with Asana ID and modified timestamp
        try:
            # Update Asana IDs in TaskWarrior without removing annotations
            tw._execute(
                tw_uuid,
                'modify',
                f'asana_id:{new_gid}',
                f'asana_modified_at:{new_mod}'
            )
            click.echo(f"  Exported TW {tw_uuid} to Asana {new_gid}")
        except Exception as e:
            click.echo(f"  Failed to update TW task {tw_uuid} after export: {e}")
    # Merge updates between Taskwarrior and Asana
    click.echo("Merging changes between Taskwarrior and Asana...")
    # Gather Taskwarrior tasks and UDA values

    # Gather Taskwarrior tasks (pending and waiting)
    tw_data = tw.load_tasks('all')
    tw_tasks = []
    for lst in tw_data.values():
        tw_tasks.extend(lst)
    for task in tw_tasks:
        # Debug: show timestamps
        tw_uuid = task.get('uuid')
        asana_gid = task.get('asana_id')
        last_sync_ts = task.get('asana_modified_at', '')
        tw_mod_ts = task.get('modified', '')
        # Continue merge logic
        if 'asana_id' not in task:
            continue
        tw_uuid = task.get('uuid')
        asana_gid = task.get('asana_id')
        last_sync_ts = task.get('asana_modified_at', '')
        last_sync_dt = iso_to_dt(last_sync_ts) or datetime.fromtimestamp(0, timezone.utc)
        tw_mod_ts = task.get('modified', '')
        tw_mod_dt = iso_to_dt(tw_mod_ts) or datetime.fromtimestamp(0, timezone.utc)
        # Fetch current Asana task
        # Fetch current Asana task (include completion)
        aresp = session.get(
            f"https://app.asana.com/api/1.0/tasks/{asana_gid}",
            params={"opt_fields": "name,notes,due_on,modified_at,completed"},
        )
        if aresp.status_code != 200:
            click.echo(f"Failed to fetch Asana task {asana_gid}: {aresp.status_code}")
            continue
        adata = aresp.json().get('data', {})
        # Sync completion/incompletion based on last-write-wins
        asana_mod_ts = adata.get('modified_at', '')
        asana_mod_dt = iso_to_dt(asana_mod_ts) or datetime.fromtimestamp(0, timezone.utc)
        completed_tw = (task.get('status') == 'completed')
        completed_asana = adata.get('completed', False)
        if completed_tw != completed_asana:
            # Determine which side changed last
            if tw_mod_dt > asana_mod_dt:
                # Push TW completion state to Asana
                try:
                    cresp = session.put(
                        f"https://app.asana.com/api/1.0/tasks/{asana_gid}",
                        json={'data': {'completed': completed_tw}}
                    )
                    cresp.raise_for_status()
                    new_mod = cresp.json().get('data', {}).get('modified_at', '')
                    tw._execute(tw_uuid, 'modify', f'asana_modified_at:{new_mod}')
                    click.echo(f"  Synced completion TW->Asana for task {tw_uuid}")
                except Exception as e:
                    click.echo(f"  Error syncing completion to Asana {asana_gid}: {e}")
            else:
                # Apply Asana completion state to TW
                try:
                    if completed_asana:
                        tw.task_done(uuid=tw_uuid)
                    else:
                        tw._execute(tw_uuid, 'modify', 'status:pending')
                except Exception:
                    pass
                try:
                    tw._execute(tw_uuid, 'modify', f'asana_modified_at:{asana_mod_ts}')
                    click.echo(f"  Synced completion Asana->TW for task {tw_uuid}")
                except Exception as e:
                    click.echo(f"  Error syncing completion to TW {tw_uuid}: {e}")
            continue
        # End completion sync
        # Determine sync direction
        # TW->Asana if TW changed since last sync and at least as recent as Asana
        if tw_mod_dt > last_sync_dt and tw_mod_dt >= asana_mod_dt:
            # Push TW changes to Asana
            tw_desc = task.get('description', '')
            if '\n\n' in tw_desc:
                name, notes = tw_desc.split('\n\n', 1)
            else:
                name, notes = tw_desc, ''
            payload = {'data': {'name': name, 'notes': notes}}
            # Normalize due date for Asana (YYYY-MM-DD)
            due_val = task.get('due')
            if due_val:
                # If already date-only, use directly
                if re.match(r'^\d{4}-\d{2}-\d{2}$', due_val):
                    payload['data']['due_on'] = due_val
                else:
                    dt_due = iso_to_dt(due_val)
                    if dt_due:
                        payload['data']['due_on'] = dt_due.date().isoformat()
                    else:
                        click.echo(f"  Warning: could not parse due date '{due_val}' for task {tw_uuid}")
            # Push TaskWarrior changes to Asana
            try:
                resp = session.put(
                    f"https://app.asana.com/api/1.0/tasks/{asana_gid}", json=payload
                )
            except Exception as e:
                click.echo(f"  Connection error updating Asana task {asana_gid}: {e}")
                continue
            if resp.status_code >= 400:
                click.echo(
                    f"  Bad Request updating Asana task {asana_gid}: "
                    f"{resp.status_code} {resp.text}"
                )
                click.echo(f"    Payload: {payload}")
                continue
            data = resp.json().get('data', {})
            new_mod = data.get('modified_at', '')
            # Update TW UDA
            try:
                # Update only the asana_modified_at UDA without affecting annotations
                tw._execute(
                    tw_uuid,
                    'modify',
                    f'asana_modified_at:{new_mod}'
                )
                click.echo(f"  Updated Asana task {asana_gid} from TW {tw_uuid}")
            except Exception as e:
                click.echo(f"  Failed to update TW 'asana_modified_at' UDA for {tw_uuid}: {e}")
        # Asana->TW if Asana changed since last sync and newer than TW
        elif asana_mod_dt > last_sync_dt and asana_mod_dt > tw_mod_dt:
            # Push Asana changes to TW
            desc = adata.get('name', '')
            notes = adata.get('notes', '')
            full_desc = desc + ('\n\n' + notes if notes else '')
            update = {'uuid': tw_uuid, 'description': full_desc}
            if adata.get('due_on'):
                update['due'] = adata.get('due_on')
            # Also update UDA
            update['asana_modified_at'] = asana_mod_ts
            # Apply Asana field updates to TW without wiping annotations
            modify_args = []
            desc = update.get('description')
            due = update.get('due')
            mod_ts = update.get('asana_modified_at')
            if desc is not None:
                modify_args.append(f'description:"{desc}"')
            if due is not None:
                modify_args.append(f'due:{due}')
            if mod_ts is not None:
                modify_args.append(f'asana_modified_at:{mod_ts}')
            try:
                tw._execute(tw_uuid, 'modify', *modify_args)
                click.echo(f"  Updated TW task {tw_uuid} from Asana {asana_gid}")
            except Exception as e:
                click.echo(f"  Failed to apply Asana->TW modify for {tw_uuid}: {e}")
        # If both changed beyond last sync, resolve by latest modification
        elif tw_mod_dt > last_sync_dt and asana_mod_dt > last_sync_dt:
            # Conflict: choose latest
            if tw_mod_dt >= asana_mod_dt:
                # Conflict resolution: push TW->Asana (last-write wins)
                try:
                    resp = session.put(
                        f"https://app.asana.com/api/1.0/tasks/{asana_gid}", json=payload
                    )
                except Exception as e:
                    click.echo(f"  Connection error resolving conflict to Asana {asana_gid}: {e}")
                    continue
                if resp.status_code >= 400:
                    click.echo(
                        f"  Bad Request resolving conflict to Asana {asana_gid}: "
                        f"{resp.status_code} {resp.text}"
                    )
                    click.echo(f"    Payload: {payload}")
                    continue
                data = resp.json().get('data', {})
                new_mod = data.get('modified_at', '')
                try:
                    # Preserve annotations while updating asana_modified_at UDA
                    tw._execute(
                        tw_uuid,
                        'modify',
                        f'asana_modified_at:{new_mod}'
                    )
                    click.echo(f"  Resolved conflict: TW->Asana for {tw_uuid}")
                except Exception as e:
                    click.echo(f"  Failed to update TW 'asana_modified_at' UDA for {tw_uuid}: {e}")
            else:
                # re-run Asana->TW block
                desc = adata.get('name', '')
                notes = adata.get('notes', '')
                full_desc = desc + ('\n\n' + notes if notes else '')
                update = {'uuid': tw_uuid, 'description': full_desc}
                if adata.get('due_on'):
                    update['due'] = adata.get('due_on')
                update['asana_modified_at'] = asana_mod_ts
                # Conflict resolution: apply Asana->TW fields similarly
                modify_args = []
                desc2 = update.get('description')
                due2 = update.get('due')
                mod_ts2 = update.get('asana_modified_at')
                if desc2 is not None:
                    modify_args.append(f'description:"{desc2}"')
                if due2 is not None:
                    modify_args.append(f'due:{due2}')
                if mod_ts2 is not None:
                    modify_args.append(f'asana_modified_at:{mod_ts2}')
                try:
                    tw._execute(tw_uuid, 'modify', *modify_args)
                    click.echo(f"  Resolved conflict: Asana->TW for {tw_uuid}")
                except Exception as e:
                    click.echo(f"  Conflict resolution modify failed for TW {tw_uuid}: {e}")
    # Import Asana comments → Taskwarrior annotations
    click.echo("Importing Asana comments into Taskwarrior annotations...")
    tw_data_all = tw.load_tasks('all')
    all_tw = [t for lst in tw_data_all.values() for t in lst]
    for task in all_tw:
        tw_uuid = task.get('uuid')
        logger.debug(f"Looking at Taskwarrior task id {tw_uuid}")
        asana_gid = task.get('asana_id')
        if not asana_gid:
            logger.debug(f"Taskwarrior task id {tw_uuid} has no Asana id, skipping.")
            continue
        logger.debug(f"Asana task id {asana_gid} found for Taskwarrior task {tw_uuid}, checking for new Asana comments.")
        # Gather already-imported Asana story GIDs and local annotation texts
        imported_gids = set()
        existing_texts = []
        for ann in task.get('annotations', []):
            desc = ann.get('description', '') or ''
            m = re.search(r'\[[^:]+:(\d+)', desc)
            if m:
                imported_gids.add(m.group(1))
            else:
                existing_texts.append(desc.strip())
        logger.debug("TW %s imported_gids: %s", tw_uuid, imported_gids)
        logger.debug("TW %s existing_texts: %s", tw_uuid, existing_texts)
        # Fetch Asana stories (comments), including author info
        try:
            resp_st = session.get(
                f"https://app.asana.com/api/1.0/tasks/{asana_gid}/stories",
                params={
                    "opt_fields":
                    "gid,created_at,type,text,created_by.gid,created_by.name"
                },
            )
        except Exception:
            continue
        if resp_st.status_code != 200:
            continue
        for story in resp_st.json().get('data', []):
            # Only import comment stories
            if story.get('type') != 'comment':
                continue
            s_gid = story.get('gid')
            # Skip comments already imported by GID
            if s_gid in imported_gids:
                continue
            text = story.get('text', '').strip()
            if not text:
                continue
            # Skip if this exact text already exists locally
            if text in existing_texts:
                continue
            # Determine author display name
            author = story.get('created_by', {}) or {}
            author_gid = author.get('gid')
            author_name = author.get('name', '')
            display_author = 'me' if author_gid == me_gid else author_name
            created_at = story.get('created_at', '')
            note = f"[{display_author}:{s_gid} @ {created_at}] {text}"
            try:
                tw.task_annotate(task, note)
                click.echo(f"  Imported comment {s_gid} by {display_author} into TW {tw_uuid}")
                imported_gids.add(s_gid)
                existing_texts.append(text)
            except Exception:
                pass
    click.echo("Pushing new Taskwarrior annotations to Asana comments...")
    # Ensure we have latest TW tasks
    tw_data_all = tw.load_tasks('all')
    all_tw = [t for lst in tw_data_all.values() for t in lst]

    for task in all_tw:
        # Identify this task's UUID for annotation commands
        tw_uuid = task.get('uuid')
        asana_gid = task.get('asana_id')
        if not asana_gid:
            continue
        # Fetch existing Asana comments
        try:
            resp_st = session.get(
                f"https://app.asana.com/api/1.0/tasks/{asana_gid}/stories",
                params={"opt_fields": "type,text"}
            )
            stories = resp_st.json().get('data', []) if resp_st.status_code == 200 else []
        except Exception:
            stories = []
        # Collect existing Asana comment texts to avoid duplicates
        existing_texts = {s['text'] for s in stories if s.get('type') == 'comment'}
        for ann in task.get('annotations', []):
            desc = ann.get('description', '').strip()
            # Skip previously imported Asana comments (marked) or empty
            if desc.startswith('[asana:') or not desc:
                continue
            # Skip if this text already exists in Asana
            if desc in existing_texts:
                continue
            # Push new local annotation to Asana
            try:
                resp_post = session.post(
                    f"https://app.asana.com/api/1.0/tasks/{asana_gid}/stories",
                    json={'data': {'text': desc}}
                )
            except Exception as e:
                click.echo(f"  Connection error posting comment to Asana task {asana_gid}: {e}")
                continue
            if resp_post.status_code >= 400:
                click.echo(f"  Failed to post TW annotation to Asana {asana_gid}: {resp_post.status_code} {resp_post.text}")
                continue
            nd = resp_post.json().get('data', {})
            new_gid = nd.get('gid')
            created_at = nd.get('created_at')
            # Determine original annotation ID via TaskWarrior JSON export (disable hooks)
            marker = f"[asana:{new_gid} @ {created_at}] {desc}"
            orig_id = None
            try:
                raw = subprocess.check_output([
                    'task', 'rc.hooks=off', f'uuid:{tw_uuid}', 'export'
                ])
                data = json.loads(raw)
                if data:
                    for a in data[0].get('annotations', []):
                        if a.get('description', '').strip() == desc:
                            orig_id = a.get('id')
                            break
            except Exception as e:
                logger.exception("Could not fetch annotations for TW %s: %s", tw_uuid, e)
            # 1) Add the marker annotation
            logger.debug("Adding marker annotation for TW %s: %s", tw_uuid, marker)
            tw.task_annotate(task, marker)
            # 2) Delete the original annotation by its numeric ID if found
            if orig_id is not None:
                try:
                    tw._execute(tw_uuid, 'annotate', str(orig_id), 'delete')
                    logger.debug("Deleted annotation id %s for TW %s", orig_id, tw_uuid)
                except Exception:
                    logger.exception("Failed to delete annotation id %s for TW %s", orig_id, tw_uuid)
            else:
                logger.warning(
                    "Original annotation ID not found for description '%s' on TW %s; manual cleanup required",
                    desc, tw_uuid
                )
            click.echo(f"  Pushed annotation to Asana and cleaned up local annotation: {desc}")
    click.echo("Sync complete.")


@cli.command('install-hook')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose debug output')
@click.pass_context
def install_hook(ctx, verbose):
    """
    Install Taskwarrior single-file hooks for add and exit to trigger Asana sync.
    This will create scripts under ~/.task/hooks/on-add-asana-warrior and ~/.task/hooks/on-exit-asana-warrior.
    """
    # If verbose for this command, increase logging
    if verbose or ctx.obj.get('verbose'):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('urllib3').setLevel(logging.DEBUG)
    logger.debug("install-hook command called")
    from taskw import TaskWarrior

    tw = TaskWarrior()

    # Reset hooks.location
    try:
        tw._execute('config', 'hooks.location', '')
        click.echo("Cleared Taskwarrior hooks.location; using default ~/.task/hooks")
    except Exception as e:
        click.echo(f"Failed to clear hooks.location: {e}")

    hooks_dir = os.path.expanduser('~/.task/hooks')
    tw._execute('config', 'hooks.location', hooks_dir)

    # Clean and recreate hooks directory
    shutil.rmtree(hooks_dir, ignore_errors=True)
    os.makedirs(hooks_dir, exist_ok=True)
    os.chmod(hooks_dir, 0o755)

    # Hook events: run on task add and on exit to trigger Asana sync
    events = ['add', 'exit']

    # Resolve executable (support install under any alias)
    exe = shutil.which('asana-warrior') or shutil.which('aw') or shutil.which('awarrior')
    if not exe:
        click.echo("WARNING: 'asana-warrior' not found in PATH; using fallback executable path.")
        exe = os.path.realpath(sys.argv[0])

    # Hook logic for add hook (simple passthrough)
    add_script = f"""#!/usr/bin/env bash
cd ~ || exit 0
stdin=$(cat)
# Avoid recursion: skip hook if sync already running
if [ -n "$ASANA_WARRIOR_RUNNING" ]; then printf "%s\\n" "$stdin"; exit 0; fi
export ASANA_WARRIOR_RUNNING=1
# Trigger sync in background without logging
nohup {exe} sync > /dev/null 2>&1 &
printf "%s\\n" "$stdin"
exit 0
"""

    # Hook logic for exit hook (no input, just trigger sync)
    exit_script = f"""#!/usr/bin/env bash
cd ~ || exit 0
# Avoid recursion: skip hook if sync already running
if [ -n "$ASANA_WARRIOR_RUNNING" ]; then exit 0; fi
export ASANA_WARRIOR_RUNNING=1
# Trigger sync in background without logging
nohup {exe} sync > /dev/null 2>&1 &
exit 0
"""

    for ev in events:
        hook_path = os.path.join(hooks_dir, f"on-{ev}-asana-warrior")

        try:
            script_content = add_script if ev == 'add' else exit_script
            with open(hook_path, 'w') as f:
                f.write(script_content)
            os.chmod(hook_path, 0o755)
            click.echo(f"Installed hook for {ev} at {hook_path}")

        except Exception as e:
            click.echo(f"Failed to install hook for {ev}: {e}")

@cli.command('uninstall-hook')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose debug output')
@click.pass_context
def uninstall_hook(ctx, verbose):
    """
    Uninstall Taskwarrior single-file hooks for add and exit to disable Asana sync.
    This will remove scripts under ~/.task/hooks/on-add-asana-warrior and ~/.task/hooks/on-exit-asana-warrior.
    """
    # If verbose for this command, increase logging
    if verbose or ctx.obj.get('verbose'):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('urllib3').setLevel(logging.DEBUG)
    logger.debug("uninstall-hook command called")
    from taskw import TaskWarrior

    tw = TaskWarrior()

    # Clear hooks.location config to reset to default
    try:
        tw._execute('config', 'hooks.location', '')
        click.echo("Cleared Taskwarrior hooks.location; using default hooks directory")
    except Exception as e:
        click.echo(f"Failed to clear hooks.location: {e}")

    hooks_dir = os.path.expanduser('~/.task/hooks')
    events = ['add', 'exit']
    for ev in events:
        hook_path = os.path.join(hooks_dir, f"on-{ev}-asana-warrior")
        try:
            if os.path.exists(hook_path):
                os.remove(hook_path)
                click.echo(f"Removed hook for {ev} at {hook_path}")
            else:
                click.echo(f"No hook for {ev} found at {hook_path}")
        except Exception as e:
            click.echo(f"Failed to remove hook for {ev}: {e}")

@cli.command('map-fields')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose debug output')
@click.pass_context
def map_fields(ctx, verbose):
    """Interactively define mappings between Asana fields (built-in and custom)
    and TaskWarrior attributes/UDAs."""
    # If verbose for this command, increase logging
    if verbose or ctx.obj.get('verbose'):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('urllib3').setLevel(logging.DEBUG)
    logger.debug("map-fields command called")
    from taskw import TaskWarrior
    import re

    # 1) Load config & session
    config = load_config()
    if not config.get('auth_type'):
        click.echo('No configuration found; run `asana-warrior configure` first.')
        return

    if config['auth_type'] == 'pat':
        session = requests.Session()
        session.headers.update({'Authorization': f"Bearer {config['asana_token']}"})
    else:
        session = OAuth2Session(
            config['client_id'],
            token=config['token'],
            redirect_uri=config['redirect_uri']
        )

    # 2) Gather custom fields from all configured Asana projects
    project_ids = config.get('projects', [])
    if not project_ids:
        click.echo('No Asana projects configured; run `asana-warrior configure` first.')
        return

    # Built-in Asana fields (excluding name/notes, due_on, completed)
    asana_fields = {
        'assignee':                  'Assignee',
        'assignee_status':           'Assignee status',
        'created_at':                'Created at',
        'modified_at':               'Modified at',
        'due_at':                    'Due time',
        'start_on':                  'Start on',
        'html_notes':                'HTML notes',
        'is_rendered_as_separator':  'Separator flag',
        'tags':                      'Tags',
        'followers':                 'Followers',
        'projects':                  'Projects',
        'workspace':                 'Workspace',
        'resource_subtype':          'Resource subtype',
        'resource_type':             'Resource type',
        'hearted':                   'Hearted by me',
        'hearts':                    'Hearts count',
        'likes':                     'Likes count',
    }

    # Merge custom fields across all configured Asana projects
    for proj_gid in project_ids:
        resp = session.get(
            f"https://app.asana.com/api/1.0/projects/{proj_gid}",
            params={'opt_fields':
                    'custom_field_settings.custom_field.gid,custom_field_settings.custom_field.name'}
        )
        if resp.status_code != 200:
            click.echo(f"Warning: failed to load custom fields for project {proj_gid}: {resp.status_code}")
            continue
        proj_data = resp.json().get('data', {})
        for cs in proj_data.get('custom_field_settings', []):
            cf = cs.get('custom_field', {})
            cf_gid = cf.get('gid')
            cf_name = cf.get('name')
            if cf_gid and cf_name:
                asana_fields[f"custom_field.{cf_gid}"] = cf_name


    # 4) Discover TaskWarrior UDAs + built-ins
    tw = TaskWarrior()
    try:
        udas = list(tw.config.get_udas().keys())
    except Exception:
        udas = []
    built_in_tw = ['description', 'project', 'due', 'priority', 'tags', 'status']
    tw_keys = built_in_tw + udas
    click.echo("\nAvailable TaskWarrior fields/UDAs: " + ", ".join(tw_keys))

    # 5) Walk the user through Asana → TW
    cfg = config.setdefault('field_mappings', {})
    atot = cfg.setdefault('asana_to_tw', {})
    click.echo("\n--- Asana → TaskWarrior mappings ---")
    create_opt = '<create new UDA>'
    for key, label in asana_fields.items():
        if not click.confirm(f"Map Asana field '{label}' ({key}) → TW?", default=False):
            continue
        # choose existing TW field/uda or create a new UDA
        choices = tw_keys + [create_opt]
        sel = click.prompt(
            f"Select or create TW field for '{label}'",
            type=click.Choice(choices)
        )
        if sel == create_opt:
            base = label.lower().replace(' ', '_')
            default_name = re.sub(r'[^a-z0-9_]', '_', base)
            name = click.prompt("Enter new UDA name", default=default_name)
            uda_type = click.prompt(
                "UDA type",
                type=click.Choice(['string', 'numeric', 'date', 'duration']),
                default='string'
            )
            uda_label = click.prompt("UDA label", default=label)
            tw = TaskWarrior()
            tw._execute('config', f"uda.{name}.type", uda_type)
            tw._execute('config', f"uda.{name}.label", uda_label)
            tw_keys.append(name)
            sel = name
        atot[key] = sel

    # 6) ...and TW → Asana
    ttoa = cfg.setdefault('tw_to_asana', {})
    click.echo("\n--- TaskWarrior → Asana mappings ---")
    af_keys = list(asana_fields.keys())
    click.echo("Available Asana fields: " + ", ".join(af_keys))
    for twk in tw_keys:
        if click.confirm(f"Map TW field \"{twk}\" → Asana?", default=False):
            sel = click.prompt("Select Asana field", type=click.Choice(af_keys))
            ttoa[twk] = sel

    # 7) Save it back
    save_config(config)
    click.echo(f"Field mappings saved to {get_config_path()}")

def main():
    cli()

if __name__ == "__main__":
    main()
