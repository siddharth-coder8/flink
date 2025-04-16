# MIT License
#
# Copyright (c) 2025 SVECTOR
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import fnmatch
import getpass
import hashlib
import json
import os
import zlib
import re
import requests
from datetime import datetime, timedelta
from urllib.parse import urlparse
from tabulate import tabulate

# Load Firebase configuration from environment variables
PROJECT_ID = os.getenv("FLINK_PROJECT_ID")
API_KEY = os.getenv("FLINK_API_KEY")
DATABASE_URL = os.getenv("FLINK_DATABASE_URL")
BUCKET_NAME = os.getenv("FLINK_BUCKET_NAME")

# Validate configuration
if not all([PROJECT_ID, API_KEY, DATABASE_URL, BUCKET_NAME]):
    raise EnvironmentError("Missing Firebase configuration. Set FLINK_PROJECT_ID, FLINK_API_KEY, FLINK_DATABASE_URL, and FLINK_BUCKET_NAME environment variables.")

# Global variables
user_id = None
id_token = None
refresh_token = None
token_expiry = None

def refresh_id_token():
    global id_token, refresh_token, token_expiry
    if not refresh_token:
        print("No refresh token available. Please login again.")
        return False
    url = f"https://securetoken.googleapis.com/v1/token?key={API_KEY}"
    payload = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            id_token = data['id_token']
            refresh_token = data['refresh_token']
            token_expiry = datetime.now() + timedelta(seconds=int(data['expires_in']))
            save_user_credentials(user_id, id_token, refresh_token, token_expiry.isoformat())
            print("Refreshed authentication token")
            return True
        else:
            print("Token refresh failed.")
            return False
    except requests.RequestException:
        print("Network error during token refresh.")
        return False

def load_user_credentials():
    global user_id, id_token, refresh_token, token_expiry
    creds_path = os.path.expanduser('~/.flink/credentials.json')
    if os.path.exists(creds_path):
        try:
            with open(creds_path, 'r') as f:
                creds = json.load(f)
                user_id = creds.get('user_id')
                id_token = creds.get('id_token')
                refresh_token = creds.get('refresh_token')
                expiry_str = creds.get('token_expiry')
                token_expiry = datetime.fromisoformat(expiry_str) if expiry_str else None
            if token_expiry and datetime.now() > token_expiry:
                refresh_id_token()
            print(f"Loaded user ID: {user_id}")
        except (json.JSONDecodeError, IOError):
            print("Error reading credentials file.")
    else:
        print("No user credentials found. Please login or register.")

def save_user_credentials(user_id, id_token, refresh_token, token_expiry):
    creds_path = os.path.expanduser('~/.flink')
    try:
        os.makedirs(creds_path, exist_ok=True)
        creds_file = os.path.join(creds_path, 'credentials.json')
        with open(creds_file, 'w') as f:
            json.dump({
                'user_id': user_id,
                'id_token': id_token,
                'refresh_token': refresh_token,
                'token_expiry': token_expiry
            }, f)
        os.chmod(creds_file, 0o600)  # Restrict permissions
        print("Saved user credentials")
    except (IOError, OSError):
        print("Error saving credentials.")

def db_set(path, data, id_token):
    if token_expiry and datetime.now() > token_expiry:
        if not refresh_id_token():
            return None
    url = f"{DATABASE_URL}/{path}.json?auth={id_token}"
    try:
        response = requests.put(url, json=data, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print("Error setting data.")
            return None
    except requests.RequestException:
        print("Network error during database write.")
        return None

def db_get(path, id_token=None):
    if id_token and token_expiry and datetime.now() > token_expiry:
        if not refresh_id_token():
            return None
    url = f"{DATABASE_URL}/{path}.json" + (f"?auth={id_token}" if id_token else "")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print("Error getting data.")
            return None
    except requests.RequestException:
        print("Network error during database read.")
        return None

def storage_upload(file_path, destination, id_token):
    if token_expiry and datetime.now() > token_expiry:
        if not refresh_id_token():
            return None
    url = f"https://storage.googleapis.com/upload/storage/v1/b/{BUCKET_NAME}/o?uploadType=media&name={destination}"
    headers = {"Authorization": f"Bearer {id_token}", "Content-Type": "application/octet-stream"}
    try:
        with open(file_path, 'rb') as f:
            response = requests.post(url, headers=headers, data=f, timeout=30)
        if response.status_code == 200:
            return response.json()
        else:
            print("Error uploading file.")
            return None
    except (IOError, requests.RequestException):
        print("Error during file upload.")
        return None

def storage_download(source, file_path, id_token=None):
    if id_token and token_expiry and datetime.now() > token_expiry:
        if not refresh_id_token():
            return False
    url = f"https://storage.googleapis.com/storage/v1/b/{BUCKET_NAME}/o/{source.replace('/', '%2F')}?alt=media"
    headers = {"Authorization": f"Bearer {id_token}"} if id_token else {}
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(response.content)
            return True
        else:
            print("Error downloading file.")
            return False
    except (IOError, requests.RequestException):
        print("Error during file download.")
        return False

def sanitize_path(base_path, path):
    """Prevent path traversal by ensuring path stays within base_path."""
    abs_base = os.path.abspath(base_path)
    abs_path = os.path.abspath(os.path.join(base_path, path))
    if not abs_path.startswith(abs_base):
        raise ValueError(f"Invalid path: {path} escapes repository directory")
    return abs_path

def find_repo_path():
    current_dir = os.getcwd()
    while current_dir != '/':
        flink_dir = os.path.join(current_dir, '.flink')
        if os.path.isdir(flink_dir) and os.path.exists(os.path.join(flink_dir, 'config')):
            return current_dir
        current_dir = os.path.dirname(current_dir)
    return None

def hash_object(data, type_):
    header = f"{type_} {len(data)}\0".encode()
    full_data = header + data
    hash_ = hashlib.sha256(full_data).hexdigest()
    return hash_, full_data

def write_object(hash_, data, repo_path):
    object_dir = os.path.join(repo_path, '.flink', 'objects', hash_[:2])
    object_path = os.path.join(object_dir, hash_[2:])
    try:
        sanitize_path(repo_path, object_path)
        os.makedirs(object_dir, exist_ok=True)
        with open(object_path, 'wb') as f:
            f.write(zlib.compress(data))
    except (ValueError, IOError):
        print(f"Error writing object {hash_}")

def read_object(hash_, repo_path):
    object_path = os.path.join(repo_path, '.flink', 'objects', hash_[:2], hash_[2:])
    try:
        sanitize_path(repo_path, object_path)
        with open(object_path, 'rb') as f:
            data = zlib.decompress(f.read())
        header, content = data.split(b'\0', 1)
        type_, _ = header.decode().split(' ', 1)
        return type_, content
    except (ValueError, IOError, FileNotFoundError):
        raise FileNotFoundError(f"Object {hash_} not found")

def create_blob(file_path, repo_path):
    try:
        sanitize_path(repo_path, file_path)
        with open(file_path, 'rb') as f:
            content = f.read()
        hash_, full_data = hash_object(content, 'blob')
        write_object(hash_, full_data, repo_path)
        return hash_
    except (ValueError, IOError):
        print(f"Error creating blob for {file_path}")
        return None

def parse_tree(data):
    entries = []
    pos = 0
    while pos < len(data):
        try:
            null_pos = data.index(b'\0', pos)
            entry_header = data[pos:null_pos].decode()
            mode, name = entry_header.split(' ', 1)
            hash_ = data[null_pos+1:null_pos+21].hex()
            entries.append((mode, name, hash_))
            pos = null_pos + 21
        except (ValueError, UnicodeDecodeError):
            break
    return entries

def create_tree(entries, repo_path):
    tree_content = b''
    for mode, name, hash_ in entries:
        try:
            tree_content += f"{mode} {name}\0".encode() + bytes.fromhex(hash_)
        except ValueError:
            print(f"Invalid hash in tree: {hash_}")
            continue
    hash_, full_data = hash_object(tree_content, 'tree')
    write_object(hash_, full_data, repo_path)
    return hash_

def build_tree_from_index(index, repo_path):
    tree_entries = {}
    for path, blob_hash in index.items():
        try:
            parts = path.split('/')
            current = tree_entries
            for i, part in enumerate(parts):
                if i == len(parts) - 1:
                    current[part] = ('100644', blob_hash)
                else:
                    if part not in current:
                        current[part] = ({}, None)
                    current = current[part][0]
        except ValueError:
            print(f"Invalid path in index: {path}")
            continue

    def create_subtree(structure):
        entries = []
        for name, value in structure.items():
            if value[1]:  # Blob
                entries.append((value[0], name, value[1]))
            else:  # Tree
                subtree_hash = create_subtree(value[0])
                entries.append(('040000', name, subtree_hash))
        return create_tree(entries, repo_path)

    return create_subtree(tree_entries)

def create_commit(tree_hash, parent_hash, author, message, repo_path):
    commit_content = f"tree {tree_hash}\n"
    if parent_hash:
        commit_content += f"parent {parent_hash}\n"
    commit_content += f"author {author}\ncommitter {author}\n\n{message}\n"
    hash_, full_data = hash_object(commit_content.encode(), 'commit')
    write_object(hash_, full_data, repo_path)
    return hash_

def get_reachable_objects(commit_hash, repo_path, objects=None):
    if objects is None:
        objects = set()
    if not commit_hash or commit_hash in objects:
        return objects
    objects.add(commit_hash)
    try:
        type_, content = read_object(commit_hash, repo_path)
        if type_ != 'commit':
            return objects
        lines = content.decode().split('\n')
        tree_hash = lines[0].split(' ')[1]
        objects.add(tree_hash)
        parent_hash = None
        for line in lines[1:]:
            if line.startswith('parent'):
                parent_hash = line.split(' ')[1]
                break
        try:
            type_, tree_data = read_object(tree_hash, repo_path)
            for mode, _, hash_ in parse_tree(tree_data):
                objects.add(hash_)
                if mode == '040000':
                    get_reachable_objects(hash_, repo_path, objects)
        except FileNotFoundError:
            pass
        if parent_hash:
            get_reachable_objects(parent_hash, repo_path, objects)
    except FileNotFoundError:
        pass
    return objects

def checkout(tree_hash, repo_path, base_path):
    try:
        type_, data = read_object(tree_hash, repo_path)
        for mode, name, hash_ in parse_tree(data):
            path = os.path.join(base_path, name)
            sanitize_path(repo_path, path)
            if mode == '100644':
                try:
                    _, content = read_object(hash_, repo_path)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, 'wb') as f:
                        f.write(content)
                except FileNotFoundError:
                    print(f"Warning: Blob {hash_} not found, skipping")
            elif mode == '040000':
                os.makedirs(path, exist_ok=True)
                checkout(hash_, repo_path, path)
    except FileNotFoundError:
        print(f"Warning: Tree {tree_hash} not found, skipping")

def validate_username(username):
    """Validate username: alphanumeric, underscores, 3-50 characters."""
    pattern = r'^[a-zA-Z0-9_]{3,50}$'
    if not re.match(pattern, username):
        raise ValueError("Username must be 3-50 alphanumeric characters or underscores")
    return username

def register(email, password, username):
    global user_id, id_token, refresh_token, token_expiry
    try:
        username = validate_username(username)
        users_data = db_get("users", id_token)
        if users_data:
            for user in users_data.values():
                if user.get('username') == username:
                    print(f"Username '{username}' is already taken. Choose another.")
                    return
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            user_id = data['localId']
            id_token = data['idToken']
            refresh_token = data['refreshToken']
            token_expiry = datetime.now() + timedelta(seconds=int(data['expiresIn']))
            user_data = {
                "email": email,
                "username": username,
                "repos": []
            }
            db_set(f"users/{user_id}", user_data, id_token)
            save_user_credentials(user_id, id_token, refresh_token, token_expiry.isoformat())
            print(f"Registered user {username} ({email})")
        else:
            print("Registration failed.")
    except (ValueError, requests.RequestException) as e:
        print(f"Error: {str(e)}")

def login(email, password):
    global user_id, id_token, refresh_token, token_expiry
    try:
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            user_id = data['localId']
            id_token = data['idToken']
            refresh_token = data['refreshToken']
            token_expiry = datetime.now() + timedelta(seconds=int(data['expiresIn']))
            save_user_credentials(user_id, id_token, refresh_token, token_expiry.isoformat())
            user_data = db_get(f"users/{user_id}", id_token)
            username = user_data.get('username', 'Not set')
            print(f"Logged in as {username} ({email})")
        else:
            print("Login failed.")
    except requests.RequestException:
        print("Network error during login.")

def set_username(username):
    global user_id, id_token
    if not user_id or not id_token:
        print("Please login or register first.")
        return
    try:
        username = validate_username(username)
        users_data = db_get("users", id_token)
        if users_data:
            for uid, user in users_data.items():
                if user.get('username') == username and uid != user_id:
                    print(f"Username '{username}' is already taken. Choose another.")
                    return
        user_data = db_get(f"users/{user_id}", id_token)
        user_data['username'] = username
        db_set(f"users/{user_id}", user_data, id_token)
        print(f"Set username to '{username}'")
    except ValueError as e:
        print(f"Error: {str(e)}")

def profile():
    global user_id, id_token
    if not user_id or not id_token:
        print("Please login or register first.")
        return
    user_data = db_get(f"users/{user_id}", id_token)
    if not user_data:
        print("User not found.")
        return
    username = user_data.get('username', 'Not set')
    email = user_data.get('email', 'N/A')
    repos = user_data.get('repos', [])
    print("User Profile")
    print("-" * 40)
    print(f"Username: {username}")
    print(f"Email: {email}")
    print("-" * 40)
    if repos:
        repo_list = []
        for repo_name in repos:
            repo_data = db_get(f"repositories/{repo_name}", id_token)
            if repo_data:
                visibility = repo_data.get('visibility', 'unknown')
                master_hash = repo_data.get('refs', {}).get('master', 'none')[:8]
                repo_list.append([repo_name, visibility, master_hash, f"https://api.flink.svector.co.in/{username}/{repo_name}"])
        if repo_list:
            print("Repositories:")
            print(tabulate(repo_list, headers=["Name", "Visibility", "Latest Commit", "URL"], tablefmt="grid"))
    else:
        print("No repositories found.")

def init(repo_name=None):
    global user_id, id_token
    if not user_id or not id_token:
        print("Please login or register first.")
        return
    repo_path = os.getcwd()
    if not repo_name:
        repo_name = os.path.basename(repo_path)
    try:
        repo_name = re.sub(r'[^a-zA-Z0-9_-]', '', repo_name)  # Sanitize repo name
        if not repo_name:
            print("Invalid repository name")
            return
        repo_path = os.path.join(repo_path, repo_name)
        sanitize_path(os.getcwd(), repo_path)
        os.makedirs(repo_path, exist_ok=True)
        flink_dir = os.path.join(repo_path, '.flink')
        os.makedirs(os.path.join(flink_dir, 'objects'), exist_ok=True)
        os.makedirs(os.path.join(flink_dir, 'refs', 'heads'), exist_ok=True)
        os.makedirs(os.path.join(flink_dir, 'refs', 'remotes', 'origin'), exist_ok=True)
        with open(os.path.join(flink_dir, 'config'), 'w') as f:
            f.write(f"repo_id = {repo_name}")
        visibility = input("Make repository public or private? (public/private): ").strip().lower()
        if visibility not in ['public', 'private']:
            print("Invalid choice. Choose 'public' or 'private'.")
            return
        repo_data = {
            "refs": {},
            "visibility": visibility,
            "owner": user_id
        }
        db_set(f"repositories/{repo_name}", repo_data, id_token)
        user_data = db_get(f"users/{user_id}", id_token)
        user_data['repos'] = user_data.get('repos', []) + [repo_name]
        db_set(f"users/{user_id}", user_data, id_token)
        print(f"Initialized {visibility} Flink repository '{repo_name}' at {repo_path}")
    except ValueError:
        print("Invalid repository path")

def add(files):
    global user_id, id_token
    if not user_id or not id_token:
        print("Please login or register first.")
        return
    repo_path = find_repo_path()
    if not repo_path:
        print("Not in a Flink repository. Please initialize one first.")
        return
    elif os.getcwd() != repo_path:
        print(f"Error: Run 'flink add .' from the repository root ({repo_path})")
        return

    index_path = os.path.join(repo_path, '.flink', 'index.json')
    index = {}
    if os.path.exists(index_path):
        try:
            with open(index_path, 'r') as f:
                index = json.load(f)
        except json.JSONDecodeError:
            index = {}

    gitignore_path = os.path.join(repo_path, '.gitignore')
    ignore_patterns = []
    if os.path.exists(gitignore_path):
        try:
            with open(gitignore_path, 'r') as f:
                ignore_patterns = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except IOError:
            print("Error reading .gitignore")

    def is_ignored(file_path):
        try:
            rel_path = os.path.relpath(file_path, repo_path).replace(os.sep, '/')
            if rel_path.startswith('.flink') or rel_path == '.flink':
                return True
            for pattern in ignore_patterns:
                if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(os.path.basename(file_path), pattern):
                    return True
            return False
        except ValueError:
            return True

    def add_file(file_path):
        if not os.path.isfile(file_path) or is_ignored(file_path):
            return
        try:
            rel_path = os.path.relpath(file_path, repo_path).replace(os.sep, '/')
            blob_hash = create_blob(file_path, repo_path)
            if blob_hash:
                index[rel_path] = blob_hash
                print(f"Staged {rel_path}")
        except ValueError:
            print(f"Invalid file path: {file_path}")

    def add_directory():
        repo_abs = os.path.abspath(repo_path)
        for root, _, filenames in os.walk(repo_abs, followlinks=False):
            root_abs = os.path.abspath(root)
            if root_abs == os.path.abspath(os.path.join(repo_abs, '.flink')) or not root_abs.startswith(repo_abs):
                continue
            for filename in filenames:
                file_path = os.path.join(root, filename)
                file_abs = os.path.abspath(file_path)
                if not file_abs.startswith(repo_abs):
                    continue
                add_file(file_path)

    if not files:
        print("No files specified")
        return
    for item in files:
        item_path = os.path.join(os.getcwd(), item)
        try:
            item_abs = sanitize_path(repo_path, item_path)
            repo_abs = os.path.abspath(repo_path)
            if item == '.':
                add_directory()
            elif os.path.isfile(item_abs):
                if not item_abs.startswith(repo_abs):
                    print(f"Error: File {item} is outside repository ({repo_path})")
                    continue
                add_file(item_abs)
            elif os.path.isdir(item_abs):
                print(f"Error: Cannot add subdirectory {item} alone; use 'flink add .' to include all files")
            else:
                print(f"Path {item} does not exist")
        except ValueError:
            print(f"Invalid path: {item}")

    try:
        with open(index_path, 'w') as f:
            json.dump(index, f, indent=2)
        print(f"Added {len(index)} file(s) to staging area")
    except IOError:
        print("Error writing index file")

def commit(message):
    global user_id, id_token
    if not user_id or not id_token:
        print("Please login or register first.")
        return
    repo_path = find_repo_path()
    if not repo_path:
        print("Not in a Flink repository")
        return
    index_path = os.path.join(repo_path, '.flink', 'index.json')
    if not os.path.exists(index_path):
        print("Nothing to commit")
        return
    try:
        with open(index_path, 'r') as f:
            index = json.load(f)
        if not index:
            print("Nothing to commit")
            return
        tree_hash = build_tree_from_index(index, repo_path)
        master_ref = os.path.join(repo_path, '.flink', 'refs', 'heads', 'master')
        parent_hash = None
        if os.path.exists(master_ref):
            with open(master_ref, 'r') as f:
                parent_hash = f.read().strip()
        user_data = db_get(f"users/{user_id}", id_token)
        username = user_data.get('username', 'unknown')
        commit_hash = create_commit(tree_hash, parent_hash, username, message, repo_path)
        with open(master_ref, 'w') as f:
            f.write(commit_hash)
        os.remove(index_path)
        print(f"Committed {commit_hash}")
    except (IOError, json.JSONDecodeError):
        print("Error during commit")

def push():
    global user_id, id_token
    if not user_id or not id_token:
        print("Please login or register first.")
        return
    repo_path = find_repo_path()
    if not repo_path:
        print("Not in a Flink repository")
        return
    try:
        with open(os.path.join(repo_path, '.flink', 'config'), 'r') as f:
            repo_id = f.read().split('=')[1].strip()
        repo_data = db_get(f"repositories/{repo_id}", id_token)
        if not repo_data:
            print(f"Repository {repo_id} does not exist in database")
            return
        if repo_data['owner'] != user_id:
            print("You do not own this repository.")
            return
        master_ref = os.path.join(repo_path, '.flink', 'refs', 'heads', 'master')
        if not os.path.exists(master_ref):
            print("Nothing to push")
            return
        with open(master_ref, 'r') as f:
            local_master = f.read().strip()
        print(f"Local master hash: {local_master}")
        remote_refs = repo_data.get('refs', {})
        remote_master = remote_refs.get('master')
        objects = get_reachable_objects(local_master, repo_path)
        if remote_master:
            remote_objects = get_reachable_objects(remote_master, repo_path)
            objects -= remote_objects
        for obj_hash in objects:
            obj_path = os.path.join(repo_path, '.flink', 'objects', obj_hash[:2], obj_hash[2:])
            storage_upload(obj_path, f"repositories/{repo_id}/objects/{obj_hash}", id_token)
            print(f"Uploaded object {obj_hash}")
        repo_data['refs']['master'] = local_master
        db_set(f"repositories/{repo_id}", repo_data, id_token)
        print(f"Updated database refs to: {{'master': '{local_master}'}}")
        with open(os.path.join(repo_path, '.flink', 'refs', 'remotes', 'origin', 'master'), 'w') as f:
            f.write(local_master)
        user_data = db_get(f"users/{user_id}", id_token)
        username = user_data.get('username', 'unknown')
        print(f"Pushed changes to https://api.flink.svector.co.in/{username}/{repo_id}")
    except (IOError, ValueError):
        print("Error during push")

def clone(repo_arg):
    global user_id, id_token
    repo_name = None
    if repo_arg.startswith("https://"):
        try:
            parsed = urlparse(repo_arg)
            if parsed.netloc != 'api.flink.svector.co.in':
                print("Invalid URL. Use https://api.flink.svector.co.in/username/repo-name")
                return
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) != 2:
                print("Invalid URL format. Use https://api.flink.svector.co.in/username/repo-name")
                return
            username, repo_name = path_parts
            users_data = db_get("users", id_token if id_token else None)
            owner_id = None
            for uid, user in (users_data or {}).items():
                if user.get('username') == username:
                    owner_id = uid
                    break
            if not owner_id:
                print(f"User '{username}' not found")
                return
            repo_data = db_get(f"repositories/{repo_name}", id_token if id_token else None)
            if not repo_data or repo_data.get('owner') != owner_id:
                print(f"Repository '{repo_name}' not found for user '{username}'")
                return
        except ValueError:
            print("Invalid URL format")
            return
    else:
        repo_name = re.sub(r'[^a-zA-Z0-9_-]', '', repo_arg)  # Sanitize repo name
        if not repo_name:
            print("Invalid repository name")
            return
        repo_data = db_get(f"repositories/{repo_name}", id_token if id_token else None)
        if not repo_data:
            print(f"Repository '{repo_name}' does not exist in database")
            return

    visibility = repo_data.get('visibility', 'public')
    owner = repo_data.get('owner')
    if visibility == 'private' and (not user_id or owner != user_id):
        print("Cannot clone private repository. Please login as the owner.")
        return

    refs = repo_data.get('refs', {})
    master_hash = refs.get('master')
    try:
        repo_path = os.path.join(os.getcwd(), repo_name)
        sanitize_path(os.getcwd(), repo_path)
        os.makedirs(repo_path, exist_ok=True)
        flink_dir = os.path.join(repo_path, '.flink')
        os.makedirs(os.path.join(flink_dir, 'objects'), exist_ok=True)
        os.makedirs(os.path.join(flink_dir, 'refs', 'heads'), exist_ok=True)
        os.makedirs(os.path.join(flink_dir, 'refs', 'remotes', 'origin'), exist_ok=True)
        with open(os.path.join(flink_dir, 'config'), 'w') as f:
            f.write(f"repo_id = {repo_name}")
        print(f"Initialized Flink repository '{repo_name}' at {repo_path}")

        if master_hash:
            downloaded = set()
            def download_object(hash_):
                obj_path = os.path.join(repo_path, '.flink', 'objects', hash_[:2], hash_[2:])
                return storage_download(f"repositories/{repo_name}/objects/{hash_}", obj_path, id_token if user_id else None)

            def download_recursive(hash_):
                if hash_ in downloaded:
                    return
                if download_object(hash_):
                    downloaded.add(hash_)
                    try:
                        type_, content = read_object(hash_, repo_path)
                        if type_ == 'commit':
                            tree_hash = content.decode().split('\n')[0].split(' ')[1]
                            download_recursive(tree_hash)
                            parent_line = [l for l in content.decode().split('\n') if l.startswith('parent')]
                            if parent_line:
                                download_recursive(parent_line[0].split(' ')[1])
                        elif type_ == 'tree':
                            for _, _, hash_ in parse_tree(content):
                                download_recursive(hash_)
                    except FileNotFoundError:
                        print(f"Warning: Object {hash_} not found, skipping")

            download_recursive(master_hash)
            with open(os.path.join(repo_path, '.flink', 'refs', 'heads', 'master'), 'w') as f:
                f.write(master_hash)
            with open(os.path.join(repo_path, '.flink', 'refs', 'remotes', 'origin', 'master'), 'w') as f:
                f.write(master_hash)
            try:
                type_, content = read_object(master_hash, repo_path)
                tree_hash = content.decode().split('\n')[0].split(' ')[1]
                checkout(tree_hash, repo_path, repo_path)
                print(f"Cloned repository {repo_name}")
            except FileNotFoundError:
                print(f"Warning: Commit {master_hash} not found, cloned empty repository")
        else:
            print(f"Cloned empty repository {repo_name}")
    except (ValueError, IOError):
        print("Error initializing repository")

def list_repos():
    global user_id, id_token
    if not user_id or not id_token:
        print("Please login or register first.")
        return
    user_data = db_get(f"users/{user_id}", id_token)
    if not user_data:
        print("User not found.")
        return
    repos = user_data.get('repos', [])
    username = user_data.get('username', 'unknown')
    if not repos:
        print("You have no repositories.")
        return
    repo_list = []
    for repo_name in repos:
        repo_data = db_get(f"repositories/{repo_name}", id_token)
        if repo_data:
            visibility = repo_data.get('visibility', 'unknown')
            master_hash = repo_data.get('refs', {}).get('master', 'none')[:8]
            repo_list.append([repo_name, visibility, master_hash, f"https://api.flink.svector.co.in/{username}/{repo_name}"])
    print("Your repositories:")
    print(tabulate(repo_list, headers=["Name", "Visibility", "Latest Commit", "URL"], tablefmt="grid"))

def search(query):
    global id_token
    query_lower = query.lower()
    repo_results = []
    repos_data = db_get("repositories", id_token if id_token else None)
    if repos_data:
        for repo_name, repo in repos_data.items():
            if query_lower in repo_name.lower() and repo.get('visibility') == 'public':
                owner_id = repo.get('owner', 'unknown')
                owner_data = db_get(f"users/{owner_id}", id_token if id_token else None)
                owner_username = owner_data.get('username', 'unknown') if owner_data else 'unknown'
                master_hash = repo.get('refs', {}).get('master', 'none')[:8]
                repo_results.append([repo_name, owner_username, master_hash, f"https://api.flink.svector.co.in/{owner_username}/{repo_name}"])
    if repo_results:
        print("Matching repositories:")
        print(tabulate(repo_results, headers=["Repo Name", "Owner", "Latest Commit", "URL"], tablefmt="grid"))
    else:
        print("No matching repositories found.")

def all_repos():
    global id_token
    repo_list = []
    repos_data = db_get("repositories", id_token if id_token else None)
    if not repos_data:
        print("No repositories found or access denied.")
        return
    for repo_name, repo in repos_data.items():
        if repo.get('visibility') == 'public':
            owner_id = repo.get('owner', 'unknown')
            owner_data = db_get(f"users/{owner_id}", id_token if id_token else None)
            owner_username = owner_data.get('username', 'unknown') if owner_data else 'unknown'
            master_hash = repo.get('refs', {}).get('master', 'none')[:8]
            repo_list.append([repo_name, owner_username, master_hash, f"https://api.flink.svector.co.in/{owner_username}/{repo_name}"])
    if repo_list:
        print("All public repositories:")
        print(tabulate(repo_list, headers=["Repo Name", "Owner", "Latest Commit", "URL"], tablefmt="grid"))
    else:
        print("No public repositories found.")

def main():
    load_user_credentials()
    parser = argparse.ArgumentParser(description="Flink: An open source version control system")
    parser.add_argument('--version', action='version', version='flink 0.3.8')
    subparsers = parser.add_subparsers(dest='command')
    register_parser = subparsers.add_parser('register', help='Register a new user')
    register_parser.add_argument('email', help='User email')
    register_parser.add_argument('username', help='User username')
    register_parser.add_argument('password', help='User password', nargs='?', default=None)
    login_parser = subparsers.add_parser('login', help='Login as a user')
    login_parser.add_argument('email', help='User email')
    login_parser.add_argument('password', help='User password', nargs='?', default=None)
    set_parser = subparsers.add_parser('set', help='Set user properties')
    set_parser.add_argument('property', choices=['username'], help='Property to set')
    set_parser.add_argument('value', help='Value to set')
    profile_parser = subparsers.add_parser('profile', help='View user profile')
    init_parser = subparsers.add_parser('init', help='Initialize a new repository')
    init_parser.add_argument('repo_name', nargs='?', default=None, help='Repository name')
    add_parser = subparsers.add_parser('add', help='Add files to staging area')
    add_parser.add_argument('files', nargs='+', help='Files to add')
    commit_parser = subparsers.add_parser('commit', help='Commit staged changes')
    commit_parser.add_argument('-m', '--message', required=True, help='Commit message')
    push_parser = subparsers.add_parser('push', help='Push changes to remote')
    clone_parser = subparsers.add_parser('clone', help='Clone a repository')
    clone_parser.add_argument('repo_arg', help='Repository name or URL')
    list_parser = subparsers.add_parser('list-repos', help='List your repositories')
    search_parser = subparsers.add_parser('search', help='Search for repositories')
    search_parser.add_argument('query', help='Search query')
    all_repos_parser = subparsers.add_parser('all-repos', help='List all public repositories')
    args = parser.parse_args()
    if args.command == 'register':
        password = args.password or getpass.getpass("Enter password: ")
        register(args.email, args.username, password)
    elif args.command == 'login':
        password = args.password or getpass.getpass("Enter password: ")
        login(args.email, password)
    elif args.command == 'set':
        if args.property == 'username':
            set_username(args.value)
    elif args.command == 'profile':
        profile()
    elif args.command == 'init':
        init(args.repo_name)
    elif args.command == 'add':
        add(args.files)
    elif args.command == 'commit':
        commit(args.message)
    elif args.command == 'push':
        push()
    elif args.command == 'clone':
        clone(args.repo_arg)
    elif args.command == 'list-repos':
        list_repos()
    elif args.command == 'search':
        search(args.query)
    elif args.command == 'all-repos':
        all_repos()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
