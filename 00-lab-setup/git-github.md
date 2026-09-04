# Git and GitHub Workflow

## Overview

This document describes the workflow used to synchronize the Cybersecurity Python Lab between different machines.

GitHub is used as the central repository to prevent data loss and maintain the complete history of the project.

---

# Repository

Repository name:

LAB-00.1

Remote platform:

GitHub

Authentication:

SSH with ED25519 keys

---

# Working Machines

The laboratory can be developed from different Kali Linux virtual machines.

## Personal Computer

Environment used for personal study and laboratory development.

## Work Computer

Environment used to continue authorized laboratory activities from the workplace.

Both environments synchronize their work through GitHub.

---

# Daily Workflow

Before starting work on any machine:

cd ~/cybersecurity-python-lab

git pull origin main

source .venv/bin/activate

This ensures that the local repository contains the latest version of the project.

---

# Saving Changes

After completing work:

git status

git add .

git commit -m "description of changes"

git push origin main

---

# Synchronization Model

Personal Kali
        |
        | git push
        v
      GitHub
        ^
        | git pull
        |
Work Kali

GitHub acts as the central synchronization point between both environments.

---

# Important Rules

1. Always execute git pull before starting work.

2. Always execute git status before committing changes.

3. Use descriptive commit messages.

4. Do not upload sensitive information.

5. Do not upload private SSH keys.

6. Do not upload API keys or passwords.

7. The Python virtual environment (.venv) must remain local.

8. Push completed work to GitHub before switching to another machine.

---

# SSH Authentication

GitHub authentication is performed using SSH keys.

Key type:

ED25519

The private key remains stored locally:

~/.ssh/id_ed25519

The public key can be registered in GitHub:

~/.ssh/id_ed25519.pub

Private keys must never be uploaded to GitHub.

---

# Objective

This workflow allows the Cybersecurity Python Lab to be developed continuously from multiple machines while maintaining:

- Version control.
- Backup of the project.
- Synchronization.
- Documentation history.
- Professional development practices.
