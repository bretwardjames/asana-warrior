# Taskwarrior ↔ Asana Sync Plugin

## Overview

This plugin provides **bidirectional sync** between **Taskwarrior** and **Asana**, allowing users to:

- **Import Asana tasks** into Taskwarrior.
- **Export select Taskwarrior tasks** (manually flagged) to Asana.
- **Sync comments** (Asana task comments ↔ Taskwarrior annotations).

The goal is to **aggregate tasks across platforms**, allowing individuals to use their **preferred tools** while syncing task details and comments across systems. This supports workflows where **freelancers or teams** interact with multiple task platforms but need centralized visibility and prioritization.

---

## Key Features

- **Two-way task sync**:
  - Tasks imported from Asana are stored in Taskwarrior with a custom `asana_id`.
  - Specific Taskwarrior tasks (not imported from Asana) can be **flagged for sync** to Asana.

- **Comment sync (bidirectional)**:
  - **Asana → Taskwarrior**:
    - Asana task comments are pulled into **Taskwarrior annotations**.
  - **Taskwarrior → Asana**:
    - New annotations in Taskwarrior (for synced tasks) are posted to Asana as comments.

- **Selective Syncing**:
  - Only tasks with an **`asana_id`** (imported from Asana) or a **specific sync flag** (e.g., tag or project) are synced.

---

## Why This Exists

- Many individuals and teams work across **multiple task management tools**:
  - Some clients use **Asana**, others use **Trello**, **Basecamp**, or **Slack/email**.
  - The individual may prefer **Taskwarrior** for personal or business tasks.
- This plugin is part of a broader initiative to create a **centralized task management hub** that **aggregates tasks** across tools, prioritizes them, and eventually provides **project status visibility** decoupled from traditional due dates.

---

## Architecture

### Components:

- **Asana API**:
  - Uses Asana's REST API and Personal Access Tokens (PAT) for authentication.

- **Taskwarrior API**:
  - Interacts with Taskwarrior using [`python-taskw`](https://github.com/ralphbean/python-taskw).

- **Sync Logic**:
  - Maintains **mapping metadata** (e.g., Asana task IDs stored as `asana_id` custom attribute in Taskwarrior).
  - **Timestamps** used for comment conflict resolution (latest wins).

---

## Planned Features

- **Task sync logic**:
  - Import Asana tasks.
  - Export flagged Taskwarrior tasks.

- **Comment sync logic**:
  - Import/export comments (Asana ↔ Taskwarrior annotations).

- **Configurable sync filters**:
  - Allow selection of which **Asana projects** or **Taskwarrior tags/projects** to sync.

---

## Setup (Planned)

1. Clone the repo.
2. (Optional) Create a virtual environment and activate it.
3. Install the package:
   ```bash
   pip install -e .
   ```
4. Run configuration:
   ```bash
   asana-warrior configure
   ```
5. (Optional) Install Taskwarrior event hooks so changes trigger Asana sync:
   ```bash
   asana-warrior install-hook
   ```
   This drops small scripts into `~/.task/hooks/{on-add,on-modify,on-delete}.d` so that
   after you add, modify, or delete tasks, `asana-warrior sync` will automatically run.
