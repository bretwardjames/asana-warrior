import click
import sys
import os
import webbrowser
import requests
from requests_oauthlib import OAuth2Session
from .config import load_config, save_config, get_config_path
import shutil
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import re

@click.group()
def cli():
    """Asana ↔ Taskwarrior sync utility."""
    pass

@cli.command()
def configure():
    """Configure Asana authentication and workspace."""
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

@cli.command()
def sync():
    """Sync tasks from Asana into Taskwarrior."""
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
    ws_list = me_data.get("workspaces", [])
    ws_name_to_gid = {w.get("name"): w.get("gid") for w in ws_list}
    ws_gid_to_name = {v: k for k, v in ws_name_to_gid.items()}
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
            # Fetch full task details
            resp_t = session.get(
                f"https://app.asana.com/api/1.0/tasks/{t_gid}",
                params={"opt_fields": "name,notes,due_on"},
            )
            if resp_t.status_code != 200:
                click.echo(f"  Failed to fetch task {t_gid}: {resp_t.status_code}")
                continue
            td = resp_t.json().get("data", {})
            desc = td.get("name", "")
            notes = td.get("notes", "")
            if notes:
                desc = f"{desc}\n\n{notes}"
            due = td.get("due_on")
            # Build TaskWarrior add kwargs
            kwargs = {"description": desc, "project": tw_project, "asana_id": t_gid}
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
        click.echo(f"Task {tw_uuid} (Asana {asana_gid}): last_sync='{last_sync_ts}', tw_mod='{tw_mod_ts}'")
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
        # Sync completion status
        completed_tw = (task.get('status') == 'completed')
        completed_asana = adata.get('completed', False)
        if completed_tw and not completed_asana:
            # Mark Asana task complete
            try:
                cresp = session.put(
                    f"https://app.asana.com/api/1.0/tasks/{asana_gid}",
                    json={'data': {'completed': True}}
                )
                cresp.raise_for_status()
                new_mod = cresp.json().get('data', {},).get('modified_at', '')
                # Update only the asana_modified_at UDA without touching annotations
                tw._execute(
                    tw_uuid,
                    'modify',
                    f'asana_modified_at:{new_mod}'
                )
                click.echo(f"  Marked Asana task {asana_gid} complete for TW {tw_uuid}")
            except Exception as e:
                click.echo(f"  Failed to mark Asana task complete: {e}")
            continue
        elif completed_asana and task.get('status') != 'completed':
            # Mark TW task done
            try:
                tw.task_done(uuid=task.get('uuid'))
                # Update only the asana_modified_at UDA without removing annotations
                tw._execute(
                    tw_uuid,
                    'modify',
                    f'asana_modified_at:{adata.get("modified_at", "")}'
                )
                click.echo(f"  Marked TW task {tw_uuid} done from Asana {asana_gid}")
            except Exception as e:
                click.echo(f"  Failed to mark TW task done: {e}")
            continue
        asana_mod_ts = adata.get('modified_at', '')
        asana_mod_dt = iso_to_dt(asana_mod_ts) or datetime.fromtimestamp(0, timezone.utc)
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
    # Reload all Taskwarrior tasks
    tw_data_all = tw.load_tasks('all')
    all_tw = []
    for lst in tw_data_all.values():
        all_tw.extend(lst)
    for task in all_tw:
        asana_gid = task.get('asana_id')
        if not asana_gid:
            continue
        # Gather existing annotation markers and texts to avoid duplicates
        imported_gids = set()
        existing_texts = set()
        for ann in task.get('annotations', []):
            desc = ann.get('description', '').strip()
            # Extract GID if already from Asana
            m = re.match(r'\[asana:(\d+)', desc)
            if m:
                imported_gids.add(m.group(1))
                # Also grab remainder text
                if '] ' in desc:
                    existing_texts.add(desc.split('] ', 1)[1])
                continue
            # Otherwise treat whole desc as local text
            if desc:
                existing_texts.add(desc)
        # Fetch Asana stories (comments)
        try:
            resp_st = session.get(
                f"https://app.asana.com/api/1.0/tasks/{asana_gid}/stories",
                params={"opt_fields": "gid,created_at,type,text"}
            )
        except Exception:
            continue
        if resp_st.status_code != 200:
            continue
        for story in resp_st.json().get('data', []):
            if story.get('type') != 'comment':
                continue
            # Skip if not a comment or already imported by GID
            if story.get('type') != 'comment':
                continue
            s_gid = story.get('gid')
            if s_gid in imported_gids:
                continue
            text = story.get('text', '').strip()
            if not text:
                continue
            note = f"[asana:{s_gid} @ {story.get('created_at','')}] {text}"
            try:
                tw.task_annotate(task, note)
                click.echo(f"  Imported comment {story['gid']} into TW {task.get('uuid')}")
            except Exception:
                pass
    click.echo("Pushing new Taskwarrior annotations to Asana comments...")
    # Ensure we have latest TW tasks
    tw_data_all = tw.load_tasks('all')
    all_tw = []
    for lst in tw_data_all.values():
        all_tw.extend(lst)

    for task in all_tw:
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
            # Annotate TW with marker for imported Asana comment
            marker = f"[asana:{new_gid} @ {created_at}] {desc}"
            try:
                tw.task_annotate(task, marker)
                click.echo(f"  Pushed annotation to Asana and marked in TW: {desc}")
            except Exception:
                pass
    click.echo("Sync complete.")


@cli.command('install-hook')
def install_hook():
    """
    Install Taskwarrior single-file hooks for add/modify/delete to trigger Asana sync.
    This will create scripts under ~/.task/hooks/{on-add-asana-warrior, on-modify-asana-warrior, on-delete-asana-warrior}.
    """
    import stat
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

    # Hook event: run on task add only to avoid recursive sync loops
    events = ['add']

    # Resolve executable
    exe = shutil.which('asana-warrior') or shutil.which('aw')
    if not exe:
        click.echo("WARNING: 'asana-warrior' not found in PATH; using fallback executable path.")
        exe = os.path.realpath(sys.argv[0])

    # Hook logic for add/delete hooks (simple passthrough)
    add_delete_script = f"""#!/usr/bin/env bash
cd ~ || exit 0
stdin=$(cat)
# Trigger sync in background without logging
nohup {exe} sync > /dev/null 2>&1 &
printf "%s\\n" "$stdin"
exit 0
"""

    # Hook logic for modify hook (use read -r for line-based splitting)
    modify_script = f"""#!/usr/bin/env bash
cd ~ || exit 0

# Read two lines (old and new task JSON)
read -r old_task
read -r new_task

# Trigger sync in background without logging
nohup {exe} sync > /dev/null 2>&1 &

# Output only the new task (to Taskwarrior)
printf "%s\\n" "$new_task"
exit 0
"""

    for ev in events:
        hook_path = os.path.join(hooks_dir, f"on-{ev}-asana-warrior")

        try:
            script_content = modify_script if ev == "modify" else add_delete_script
            with open(hook_path, 'w') as f:
                f.write(script_content)
            os.chmod(hook_path, 0o755)
            click.echo(f"Installed hook for {ev} at {hook_path}")

        except Exception as e:
            click.echo(f"Failed to install hook for {ev}: {e}")

def main():
    cli()

if __name__ == "__main__":
    main()
