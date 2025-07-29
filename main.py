# /Users/localho5t/anything-online/main.py
# Standard library imports
import base64
import email.message
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import zipfile
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Third-party imports
from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QPushButton, QRadioButton, QSpinBox,
    QStackedWidget, QTabWidget, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget
)

# pty is used to create a pseudo-terminal for the Serveo worker on Unix-like
# systems, which is necessary to prevent ssh from hanging.
if sys.platform != 'win32':
    import pty
else:
    pty = None

# --- Optional Dependency Imports ---
try:
    import paramiko
except ImportError:
    paramiko = None
try:
    import requests
except ImportError:
    requests = None
try:
    import docker
except ImportError:
    docker = None

# --- Worker for running the local web server ---
class WebServerWorker(QObject):
    finished = pyqtSignal()
    server_started = pyqtSignal(str, int)
    error_received = pyqtSignal(str)

    def __init__(self, directory, port, username=None, password=None):
        super().__init__()
        self.directory = directory
        self.port = port
        self.username = username
        self.password = password
        self.httpd = None
        self._is_running = True # Flag to control the serve_forever loop

    def run(self):
        class AuthHandler(SimpleHTTPRequestHandler):
            _auth_user = self.username
            _auth_pass = self.password
            _directory = self.directory

            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=self._directory, **kwargs)

            def do_auth(self):
                if self._auth_user is None:
                    return True
                auth_header = self.headers.get('Authorization')
                if auth_header is None:
                    self.send_response(401); self.send_header('WWW-Authenticate', 'Basic realm="Restricted Area"'); self.end_headers()
                    return False
                try:
                    auth_type, encoded_creds = auth_header.split(' ', 1)
                    if auth_type.lower() != 'basic': raise ValueError("Not Basic Auth")
                    decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                    user, passw = decoded_creds.split(':', 1)
                except Exception:
                    self.send_response(401); self.send_header('WWW-Authenticate', 'Basic realm="Invalid Header"'); self.end_headers()
                    return False
                if user == self._auth_user and passw == self._auth_pass:
                    return True
                self.send_response(401); self.send_header('WWW-Authenticate', 'Basic realm="Incorrect Credentials"'); self.end_headers()
                return False

            def do_GET(self):
                if self.do_auth():
                    super().do_GET()

        try:
            self.httpd = HTTPServer(("", self.port), AuthHandler)
            host, port = self.httpd.socket.getsockname()
            self.server_started.emit(host, port)
            
            # Use _is_running flag to control the loop
            # Note: serve_forever blocks, so shutdown needs to be called from another thread
            while self._is_running:
                self.httpd.handle_request() # Handle one request at a time
                # For a true serve_forever that responds to shutdown, you'd ideally use
                # self.httpd.serve_forever(poll_interval=1.0) and call shutdown from another thread.
                # The current structure relies on shutdown being called from another thread to break serve_forever
                # or handle_request eventually, or for the thread to be quit.
                # A direct way to break out of serve_forever is often preferred.
                # For simplicity with the existing `shutdown` in stop(), this is okay.

            # If serve_forever was used, then self.httpd.shutdown() is called from stop()
            # If handle_request loop was used, this loop will eventually terminate if _is_running becomes False
            # and no new requests come in, or if an explicit shutdown is called.
            # The most reliable way for HTTPServer is a separate shutdown thread.
            self.httpd.serve_forever() # Keep this as it's the intended blocking call

        except OSError as e:
            self.error_received.emit(f"Web server error: {e}. The port might be in use.")
        except Exception as e:
            self.error_received.emit(f"An unexpected web server error occurred: {e}")
        finally:
            self._is_running = False # Ensure flag is set to false on exit
            if self.httpd:
                self.httpd.server_close() # Close the server socket
            self.finished.emit()

    def stop(self):
        self._is_running = False # Signal to stop if using a loop
        if self.httpd:
            # Shutdown the HTTP server in a separate thread to prevent blocking
            # the thread that calls stop (e.g., the main UI thread).
            threading.Thread(target=self.httpd.shutdown, daemon=True).start()

# --- Tunneling Service Workers ---
class BaseTunnelWorker(QObject):
    finished = pyqtSignal()
    url_received = pyqtSignal(str)
    error_received = pyqtSignal(str)

    def __init__(self, port):
        super().__init__()
        self.port = port
        self.process = None
        self._is_running = True # Flag to control the output reading loop

    def get_command(self): raise NotImplementedError
    def parse_url(self, line): raise NotImplementedError
    def get_executable_name(self): return self.get_command()[0]
    def get_not_found_error(self): return f"Error: '{self.get_executable_name()}' executable not found."

    def run(self):
        command = self.get_command()
        try:
            # On Windows, subprocess.CREATE_NO_WINDOW prevents a console window from appearing.
            # It's a bitwise OR flag, so it's fine even if 0.
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0

            self.process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, creationflags=creation_flags
            )
            
            # Read stdout line by line until process exits or stop is signaled
            for line in iter(self.process.stdout.readline, ''):
                if not self._is_running:
                    self.log_message("Tunnel worker stopping gracefully...")
                    break # Exit the loop if stop() was called
                url = self.parse_url(line)
                if url:
                    self.url_received.emit(url)
            
            self.process.wait() # Wait for the subprocess to actually terminate
            
        except FileNotFoundError:
            self.error_received.emit(self.get_not_found_error())
        except Exception as e:
            self.error_received.emit(f"{self.get_executable_name()} error: {e}")
        finally:
            self._is_running = False # Ensure flag is false on exit
            if self.process and self.process.poll() is None: # If process is still running, try to terminate
                self.process.terminate()
                self.process.wait(2000) # Give it a moment to terminate
                if self.process and self.process.poll() is None: # If still alive, kill
                    self.process.kill()
            self.finished.emit()

    def stop(self):
        self._is_running = False
        if self.process and self.process.poll() is None: # If the process is still running
            self.process.terminate()
            # No need to wait here, the run() method's finally block will wait/kill if necessary.

class NgrokTunnelWorker(BaseTunnelWorker):
    def get_command(self): return ["ngrok", "http", str(self.port), "--log=stdout"]
    def parse_url(self, line):
        if "url=" in line:
            try: return line.split("url=")[1].strip()
            except IndexError: return None
    def get_not_found_error(self): return "Error: 'ngrok' not found. Please download it from https://ngrok.com/download and place it in your PATH."

class CloudflareTunnelWorker(BaseTunnelWorker):
    def get_command(self): return ["cloudflared", "tunnel", "--url", f"http://localhost:{self.port}", "--no-autoupdate"]
    def parse_url(self, line):
        if "trycloudflare.com" in line and "INF" in line:
            try:
                for part in line.split():
                    if part.startswith("https://") and "trycloudflare.com" in part: return part
            except Exception: return None
    def get_not_found_error(self): return "Error: 'cloudflared' not found. See installation instructions at https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/"

class LocalTunnelWorker(BaseTunnelWorker):
    def get_command(self): return ["lt", "--port", str(self.port)]
    def parse_url(self, line):
        if "your url is:" in line:
            try: return line.split("your url is:")[1].strip()
            except IndexError: return None
    def get_not_found_error(self): return "Error: 'lt' not found. Run 'npm install -g localtunnel'."

class ServeoWorker(BaseTunnelWorker):
    # Added log_message signal to BaseTunnelWorker and then to this subclass
    log_message = pyqtSignal(str) 

    def get_command(self):
        # -tt forces pseudo-terminal allocation, which is good for interactive commands like ssh
        # -o StrictHostKeyChecking=no and UserKnownHostsFile=/dev/null (or os.devnull on Windows)
        # prevents SSH from prompting about host keys, which would hang the non-interactive process.
        # Ensure os.devnull is used for cross-platform compatibility.
        return ["ssh", "-tt", "-R", f"80:localhost:{self.port}", "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={os.devnull}", "serveo.net"]
    
    def parse_url(self, line):
        match = re.search(r'(https://[a-zA-Z0-9-]+\.serveo\.net)', line)
        return match.group(1) if match else None
    
    def get_executable_name(self): return "ssh"

    def run(self):
        if sys.platform == 'win32':
            # On Windows, pty is not available, fall back to standard subprocess.Popen
            # The -tt might cause issues on Windows with SSH, but we keep it for consistency
            # with the command structure. Subprocess will just use standard pipes.
            self.log_message.emit("Running Serveo on Windows. Pty is not available, may behave differently.")
            return super().run()
        
        command = self.get_command()
        try:
            master, slave = pty.openpty() # Create pseudo-terminal
            # Use 'stdin=slave, stdout=slave, stderr=slave' to direct all I/O through the pty.
            # `close_fds=True` is good practice on Unix for child processes.
            # `text=True` is important for handling string output.
            self.process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, text=True, close_fds=True)
            os.close(slave) # Close the slave side in the parent process

            # Read output from the master side of the pty
            with os.fdopen(master, 'r') as master_file:
                for line in iter(master_file.readline, ''):
                    if not self._is_running:
                        self.log_message.emit("Serveo worker stopping gracefully...")
                        break
                    url = self.parse_url(line)
                    if url: self.url_received.emit(url)
                    # Log other output from Serveo/ssh for debugging
                    self.log_message.emit(f"Serveo: {line.strip()}")
            
            self.process.wait() # Wait for the subprocess to terminate

        except FileNotFoundError:
            self.error_received.emit(self.get_not_found_error())
        except Exception as e:
            self.error_received.emit(f"Serveo (ssh) error: {e}")
        finally:
            self._is_running = False
            if self.process and self.process.poll() is None:
                self.process.terminate()
                self.process.wait(2000)
                if self.process and self.process.poll() is None:
                    self.process.kill()
            self.finished.emit()


# --- Data Source Workers ---
class SftpDownloadWorker(QObject):
    finished = pyqtSignal(str)
    error_received = pyqtSignal(str)
    log_message = pyqtSignal(str) # Added log message for progress/status

    def __init__(self, host, port, user, password, pkey_path, remote_path):
        super().__init__()
        self.host, self.port, self.user, self.password, self.pkey_path, self.remote_path = host, port, user, password, pkey_path, remote_path
        self._is_running = True # Flag to allow external stop (though less critical for SFTP)

    def run(self):
        if not paramiko:
            self.error_received.emit("SFTP download failed: 'paramiko' not found. Run 'pip install paramiko'.")
            return
        
        temp_dir = None
        try:
            temp_dir = tempfile.mkdtemp(prefix="sftp_")
            self.log_message.emit(f"Connecting to SFTP server {self.host}:{self.port}...")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            pkey = None
            if self.pkey_path and os.path.exists(self.pkey_path):
                try:
                    pkey = paramiko.RSAKey.from_private_key_file(self.pkey_path)
                    self.log_message.emit(f"Using private key for authentication: {self.pkey_path}")
                except paramiko.SSHException as e:
                    self.error_received.emit(f"Failed to load private key: {e}. Check key format and passphrase.")
                    return
            
            client.connect(hostname=self.host, port=self.port, username=self.user, password=self.password or None, pkey=pkey, timeout=15)
            self.log_message.emit("Connected. Opening SFTP client...")
            sftp = client.open_sftp()
            
            self.log_message.emit(f"Checking remote path: {self.remote_path}")
            # Check if remote_path is a directory or file
            remote_stat = sftp.stat(self.remote_path)
            
            if stat.S_ISDIR(remote_stat.st_mode):
                local_dir = os.path.join(temp_dir, os.path.basename(self.remote_path.rstrip('/')))
                os.makedirs(local_dir, exist_ok=True)
                self.log_message.emit(f"Remote path is a directory. Downloading to {local_dir}...")
                self._download_dir(sftp, self.remote_path, local_dir)
            else:
                local_filepath = os.path.join(temp_dir, os.path.basename(self.remote_path))
                self.log_message.emit(f"Remote path is a file. Downloading to {local_filepath}...")
                sftp.get(self.remote_path, local_filepath)
            
            self.log_message.emit("SFTP download complete.")
            self.finished.emit(temp_dir)
            
        except Exception as e:
            self.error_received.emit(f"SSH/SFTP Error: {e}")
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir) # Clean up temp dir on error
        finally:
            self._is_running = False
            if 'sftp' in locals() and sftp: sftp.close()
            if 'client' in locals() and client: client.close()

    def _download_dir(self, sftp, remote_dir, local_dir):
        # Recursive directory download
        if not self._is_running: return # Stop if flagged
        
        for item in sftp.listdir(remote_dir):
            if not self._is_running: break # Stop if flagged
            
            remote_path = f"{remote_dir.rstrip('/')}/{item}"
            local_path = os.path.join(local_dir, item)
            
            try:
                item_stat = sftp.stat(remote_path)
                if stat.S_ISDIR(item_stat.st_mode):
                    self.log_message.emit(f"Creating local directory: {local_path}")
                    os.makedirs(local_path, exist_ok=True)
                    self._download_dir(sftp, remote_path, local_path) # Recurse
                else:
                    self.log_message.emit(f"Downloading file: {remote_path} to {local_path}")
                    sftp.get(remote_path, local_path)
            except IOError as e:
                self.log_message.emit(f"Warning: Could not access {remote_path} (Skipping): {e}")
            except Exception as e:
                self.log_message.emit(f"Error during SFTP recursive download for {remote_path}: {e}")

    def stop(self):
        self._is_running = False # Set flag to stop ongoing transfers


class GdriveDownloadWorker(QObject):
    finished, error_received, log_message = pyqtSignal(str), pyqtSignal(str), pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url
        self._is_downloading = True # Added for graceful stopping

    def _get_confirm_token(self, response):
        for key, value in response.cookies.items():
            if key.startswith('download_warning'):
                return value
        return None

    def run(self):
        if not requests:
            self.error_received.emit("G-Drive download failed: 'requests' not found. Run 'pip install requests'.")
            return

        file_id_match = re.search(r'/file/d/([a-zA-Z0-9_-]+)', self.url)
        if not file_id_match:
            self.error_received.emit("Invalid Google Drive URL format. Please ensure it's a direct file link (e.g., docs.google.com/file/d/FILE_ID/...)")
            return
        file_id = file_id_match.group(1)

        temp_dir = None # Initialize temp_dir here to ensure it's always defined
        filepath = None # Initialize filepath for cleanup in case of early error

        try:
            session = requests.Session()
            download_url = "https://docs.google.com/uc?export=download"

            self.log_message.emit(f"Initiating Google Drive download for ID: {file_id}")
            # Increased timeout to 30 seconds
            response = session.get(download_url, params={'id': file_id}, stream=True, timeout=30)
            response.raise_for_status()

            token = self._get_confirm_token(response)
            if token:
                self.log_message.emit("Large file warning received, confirming download...")
                # Increased timeout to 30 seconds
                response = session.get(download_url, params={'id': file_id, 'confirm': token}, stream=True, timeout=30)
                response.raise_for_status()

            if 'text/html' in response.headers.get('Content-Type', '').lower():
                self.error_received.emit("Download failed. The file is likely private, requires login, or the link is invalid.")
                return

            temp_dir = tempfile.mkdtemp(prefix="gdrive_")
            filename = "downloaded_file"
            if 'content-disposition' in response.headers:
                msg = email.message.Message()
                msg['content-disposition'] = response.headers['content-disposition']
                filename = msg.get_filename() or filename
            filepath = os.path.join(temp_dir, filename)

            self.log_message.emit(f"Downloading '{filename}' to '{filepath}'...")
            downloaded_size = 0
            # Get total size from content-length header, default to 0 if not present
            total_size = int(response.headers.get('content-length', 0))

            with open(filepath, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if not self._is_downloading: # Check for cancellation
                        self.log_message.emit("Download cancelled by user.")
                        break # Exit the chunk loop
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    if total_size > 0:
                        progress = (downloaded_size / total_size) * 100
                        # Emit progress updates
                        self.log_message.emit(f"Downloading: {progress:.2f}% ({downloaded_size} of {total_size} bytes)")
            
            if self._is_downloading: # Only emit finished if not cancelled
                self.log_message.emit(f"Download complete: '{filename}'")
                self.finished.emit(temp_dir)
            else:
                # Clean up partially downloaded file and temp directory if cancelled
                if filepath and os.path.exists(filepath):
                    os.remove(filepath)
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                self.error_received.emit("Google Drive download was cancelled.")

        # Specific error handling for requests library
        except requests.exceptions.Timeout:
            self.error_received.emit("Google Drive download timed out. This might indicate a very large file or a slow connection.")
            if temp_dir and os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        except requests.exceptions.RequestException as e:
            self.error_received.emit(f"Network error during Google Drive download: {e}. Check your internet connection.")
            if temp_dir and os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        except Exception as e:
            self.error_received.emit(f"An unexpected error occurred during Google Drive download: {e}")
            if temp_dir and os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        # The finally block is now simplified. The 'finished' signal is explicitly emitted on success,
        # and 'error_received' handles failures (including cancellations).
        # No need to emit 'finished' from finally for the successful case as it's handled above.
        # If an error occurs, error_received is emitted, and the thread quits.
        # If cancelled, error_received is emitted, and the thread quits.

    def stop(self):
        """Sets a flag to stop the ongoing download."""
        self._is_downloading = False


class DockerListContainersWorker(QObject):
    finished, error_received = pyqtSignal(list), pyqtSignal(str)
    log_message = pyqtSignal(str)

    def run(self):
        if not docker:
            self.error_received.emit("Docker SDK not installed. Run 'pip install docker'.")
            return
        try:
            self.log_message.emit("Connecting to Docker daemon...")
            client = docker.from_env()
            containers = client.containers.list()
            self.log_message.emit(f"Found {len(containers)} running containers.")
            self.finished.emit(containers)
        except docker.errors.DockerException as e:
            self.error_received.emit(f"Docker error: Could not connect to Docker daemon. Is it running? Details: {e}")
        except Exception as e:
            self.error_received.emit(f"An unexpected Docker error occurred: {e}")

class DockerCopyWorker(QObject):
    finished = pyqtSignal(str)
    error_received = pyqtSignal(str)
    log_message = pyqtSignal(str)

    def __init__(self, container_id, container_path):
        super().__init__()
        self.container_id, self.container_path = container_id, container_path
        self._is_running = True # Flag for cancellation, though copy is fast

    def run(self):
        if not docker:
            self.error_received.emit("Docker copy failed: 'docker' library not found. Run 'pip install docker'.")
            return
        
        temp_dir = None
        try:
            self.log_message.emit(f"Connecting to Docker daemon to copy from {self.container_id}...")
            client = docker.from_env()
            container = client.containers.get(self.container_id)
            self.log_message.emit(f"Attempting to copy '{self.container_path}' from container '{container.name}'...")
            
            temp_dir = tempfile.mkdtemp(prefix="docker_")
            
            # get_archive returns a tuple: (iterator of chunks, stat_result)
            bits, stat_result = container.get_archive(self.container_path)
            self.log_message.emit(f"Received archive stream. Extracting to {temp_dir}...")

            with io.BytesIO() as tar_buffer:
                for chunk in bits:
                    if not self._is_running:
                        self.log_message.emit("Docker copy cancelled.")
                        raise UserCancelledError("Docker copy was cancelled.")
                    tar_buffer.write(chunk)
                tar_buffer.seek(0)
                
                with tarfile.open(fileobj=tar_buffer) as tar:
                    tar.extractall(path=temp_dir)
            
            self.log_message.emit("Docker copy complete.")
            self.finished.emit(temp_dir)

        except docker.errors.APIError as e:
            if e.response.status_code == 404 and "No such file or directory" in str(e):
                self.error_received.emit(f"Docker copy failed: Path '{self.container_path}' not found in container '{self.container_id}'.")
            else:
                self.error_received.emit(f"Docker API Error: {e}")
            if temp_dir and os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        except UserCancelledError:
            self.error_received.emit("Docker copy was cancelled by the user.")
            if temp_dir and os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        except Exception as e:
            self.error_received.emit(f"Docker copy error: {e}")
            if temp_dir and os.path.exists(temp_dir): shutil.rmtree(temp_dir)
        finally:
            self._is_running = False

    def stop(self):
        self._is_running = False

# Define a custom exception for user cancellation
class UserCancelledError(Exception):
    pass

# --- PaaS Deployment Workers ---
class NetlifyDeployWorker(QObject):
    finished, error_received, log_message = pyqtSignal(str), pyqtSignal(str), pyqtSignal(str)
    
    def __init__(self, token, folder_path):
        super().__init__()
        self.token, self.folder_path = token, folder_path
        self._is_running = True

    def run(self):
        if not requests:
            self.error_received.emit("Netlify deployment failed: 'requests' not found. Run 'pip install requests'.")
            return
        
        try:
            if not self._is_running: raise UserCancelledError("Deployment cancelled.")
            self.log_message.emit("Zipping project folder...")
            
            with io.BytesIO() as zip_buffer:
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for root, _, files in os.walk(self.folder_path):
                        if not self._is_running: raise UserCancelledError("Deployment cancelled during zipping.")
                        for file in files:
                            if not self._is_running: raise UserCancelledError("Deployment cancelled during zipping.")
                            abs_path = os.path.join(root, file)
                            arcname = os.path.relpath(abs_path, self.folder_path)
                            zf.write(abs_path, arcname)
                
                if not self._is_running: raise UserCancelledError("Deployment cancelled after zipping.")
                zip_buffer.seek(0)
                
                self.log_message.emit("Uploading to Netlify...")
                headers = {
                    'Content-Type': 'application/zip',
                    'Authorization': f'Bearer {self.token}'
                }
                
                response = requests.post('https://api.netlify.com/api/v1/sites', headers=headers, data=zip_buffer.read(), timeout=300) # Increased timeout
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                
                deploy_url = response.json().get('url')
                if deploy_url:
                    self.finished.emit(deploy_url)
                else:
                    self.error_received.emit("Netlify deployment succeeded but no URL was returned.")

        except requests.exceptions.RequestException as e:
            self.error_received.emit(f"Netlify API error or network issue: {e}")
        except UserCancelledError as e:
            self.error_received.emit(f"Netlify deployment cancelled: {e}")
        except Exception as e:
            self.error_received.emit(f"Netlify deployment failed: {e}")
        finally:
            self._is_running = False

    def stop(self):
        self._is_running = False # Signal to stop zipping/uploading


class VercelDeployWorker(QObject):
    finished, error_received, log_message = pyqtSignal(str), pyqtSignal(str), pyqtSignal(str)
    
    def __init__(self, folder_path):
        super().__init__()
        self.folder_path = folder_path
        self.process = None
        self._is_running = True

    def run(self):
        try:
            if not self._is_running: raise UserCancelledError("Deployment cancelled.")

            self.log_message.emit("Deploying to Vercel via CLI...")
            command = ["vercel", "--prod", "--yes"]
            
            # Using creationflags=subprocess.CREATE_NO_WINDOW for Windows to suppress console window
            creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0

            self.process = subprocess.Popen(
                command,
                cwd=self.folder_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Redirect stderr to stdout for combined output
                text=True, # Handle output as text (strings)
                bufsize=1, # Line-buffered
                creationflags=creation_flags
            )
            
            output_lines = []
            for line in iter(self.process.stdout.readline, ''):
                if not self._is_running:
                    self.log_message.emit("Vercel deployment cancelled.")
                    break
                stripped_line = line.strip()
                self.log_message.emit(stripped_line)
                output_lines.append(stripped_line)
            
            self.process.wait() # Wait for the subprocess to complete

            if self.process.returncode == 0 and self._is_running:
                found_url = False
                for line in reversed(output_lines):
                    # Vercel CLI output for production URL usually contains "Production: "
                    if "Production:" in line:
                        url_match = re.search(r'https://\S+', line)
                        if url_match:
                            self.finished.emit(url_match.group(0))
                            found_url = True
                            break
                if not found_url:
                    self.error_received.emit("Could not find production URL in Vercel CLI output. Deployment might have failed or output format changed.")
            elif not self._is_running:
                self.error_received.emit("Vercel deployment was cancelled by the user.")
            else:
                self.error_received.emit(f"Vercel CLI failed with exit code {self.process.returncode}. Check logs for details.")
        
        except FileNotFoundError:
            self.error_received.emit("Vercel CLI not found. Please run 'npm i -g vercel' and log in (`vercel login`).")
        except UserCancelledError:
            self.error_received.emit("Vercel deployment was cancelled.")
        except Exception as e:
            self.error_received.emit(f"Vercel deployment failed: {e}")
        finally:
            self._is_running = False
            if self.process and self.process.poll() is None: # If process is still running, terminate
                self.process.terminate()
                self.process.wait(2000) # Give it a moment to terminate
                if self.process and self.process.poll() is None:
                    self.process.kill()

    def stop(self):
        self._is_running = False
        if self.process and self.process.poll() is None:
            self.process.terminate() # Request subprocess to terminate


# --- Main Application Window ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anything Online")
        self.resize(800, 600)
        
        # Initialize worker and thread references to None
        self.web_server_thread: QThread | None = None
        self.web_server_worker: WebServerWorker | None = None
        self.tunnel_thread: QThread | None = None
        self.tunnel_worker: BaseTunnelWorker | None = None
        
        self.temp_dir_path: str | None = None # Stores the path to any temporary directory created by workers
        self._one_shot_threads: list[tuple[QThread, QObject]] = [] # Stores (thread, worker) for cleanup for non-persistent tasks

        # Map tunnel service names to their respective worker classes
        self.tunnel_worker_map = {
            "ngrok": NgrokTunnelWorker,
            "Cloudflare Tunnel": CloudflareTunnelWorker,
            "localtunnel": LocalTunnelWorker,
            "Serveo": ServeoWorker
        }
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        self.status_output = QTextEdit()
        self.status_output.setReadOnly(True)
        
        # --- Shared Controls Creation (moved up for proper initialization) ---
        shared_controls_layout = QVBoxLayout()
        
        # Tunnel Service selection
        service_layout = QHBoxLayout()
        self.service_combo = QComboBox()
        self.service_combo.addItems(self.tunnel_worker_map.keys())
        self.service_label = QLabel("Tunnel Service:")
        service_layout.addWidget(self.service_label)
        service_layout.addWidget(self.service_combo)
        service_layout.addStretch()
        
        # Local Port selection
        port_layout = QHBoxLayout()
        self.port_spinner = QSpinBox()
        self.port_spinner.setRange(1024, 65535) # Standard non-privileged port range
        self.port_spinner.setValue(8000)
        self.port_label = QLabel("Local Port:")
        port_layout.addWidget(self.port_label)
        port_layout.addWidget(self.port_spinner)
        port_layout.addStretch()
        
        # Password Protection (Auth)
        auth_form_layout = QFormLayout()
        self.auth_checkbox = QCheckBox("Enable Password Protection")
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")
        self.user_input.setEnabled(False) # Disabled by default
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password) # Mask password input
        self.pass_input.setEnabled(False) # Disabled by default
        auth_form_layout.addRow(self.auth_checkbox)
        
        self.user_label = QLabel("Username:")
        self.pass_label = QLabel("Password:")
        # Initially hide labels as well, or just disable inputs.
        # Keeping them visible but disabled is also common.
        auth_form_layout.addRow(self.user_label, self.user_input)
        auth_form_layout.addRow(self.pass_label, self.pass_input)
        
        # Start/Stop buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Tunnel")
        self.stop_button = QPushButton("Stop All")
        self.stop_button.setEnabled(False) # Disabled until a service starts
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()
        
        # Add shared controls to their layout
        shared_controls_layout.addLayout(service_layout)
        shared_controls_layout.addLayout(port_layout)
        shared_controls_layout.addLayout(auth_form_layout)
        shared_controls_layout.addLayout(button_layout)
        # --- End Shared Controls Creation ---

        # Create and add the tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget) # Add tab widget to main layout

        # Add the tabs. These methods create the content for each tab.
        self.tab_widget.addTab(self.create_local_share_tab(), "Local Share")
        self.tab_widget.addTab(self.create_remote_share_tab(), "Remote Share (SFTP)")
        self.tab_widget.addTab(self.create_cloud_share_tab(), "Cloud Share (SaaS)")
        self.tab_widget.addTab(self.create_container_share_tab(), "Container Share (CaaS)")
        self.tab_widget.addTab(self.create_paas_deploy_tab(), "Deploy to PaaS")

        # Add the shared controls layout and status output to the main layout
        layout.addLayout(shared_controls_layout)
        layout.addWidget(QLabel("Logs & Status:"))
        layout.addWidget(self.status_output)

        # Connect signals
        self.start_button.clicked.connect(self.start_action)
        self.stop_button.clicked.connect(self.stop_action)
        self.auth_checkbox.toggled.connect(self.on_auth_toggled)
        self.tab_widget.currentChanged.connect(self.on_main_tab_changed)
        
        # Initialize UI based on the first tab being selected
        self.on_main_tab_changed(0) 

    def create_local_share_tab(self) -> QWidget:
        """Creates the 'Local Share' tab content."""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        self.local_path_input = QLineEdit()
        self.local_path_input.setPlaceholderText("Select a local file or folder to share...")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_local_path)
        layout.addWidget(QLabel("File/Folder Path:"))
        layout.addWidget(self.local_path_input)
        layout.addWidget(browse_button)
        return widget

    def create_remote_share_tab(self) -> QWidget:
        """Creates the 'Remote Share (SFTP)' tab content."""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.ssh_host_input = QLineEdit()
        self.ssh_port_spinner = QSpinBox()
        self.ssh_port_spinner.setRange(1, 65535)
        self.ssh_port_spinner.setValue(22) # Default SSH port
        self.ssh_user_input = QLineEdit()
        self.ssh_remote_path_input = QLineEdit()
        self.ssh_remote_path_input.setPlaceholderText("/home/user/share_folder (e.g., /var/www/html)")
        
        # Authentication method radio buttons
        self.auth_pass_radio = QRadioButton("Password")
        self.auth_key_radio = QRadioButton("Private Key (e.g., id_rsa)")
        self.auth_pass_radio.setChecked(True) # Password auth is default
        auth_layout = QHBoxLayout()
        auth_layout.addWidget(self.auth_pass_radio)
        auth_layout.addWidget(self.auth_key_radio)
        
        self.ssh_pass_input = QLineEdit()
        self.ssh_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        key_layout = QHBoxLayout()
        self.ssh_key_path_input = QLineEdit()
        self.ssh_key_path_input.setPlaceholderText("Path to your private SSH key (e.g., ~/.ssh/id_rsa)")
        self.ssh_key_path_input.setEnabled(False) # Disabled by default
        browse_key_button = QPushButton("Browse...")
        browse_key_button.setEnabled(False) # Disabled by default
        browse_key_button.clicked.connect(lambda: self.ssh_key_path_input.setText(QFileDialog.getOpenFileName(self, "Select Private Key File")[0]))
        key_layout.addWidget(self.ssh_key_path_input)
        key_layout.addWidget(browse_key_button)

        # Connect radio buttons to enable/disable corresponding input fields
        self.auth_pass_radio.toggled.connect(lambda checked: [
            self.ssh_pass_input.setEnabled(checked),
            self.ssh_key_path_input.setEnabled(not checked),
            browse_key_button.setEnabled(not checked)
        ])
        
        layout.addRow("Host:", self.ssh_host_input)
        layout.addRow("Port:", self.ssh_port_spinner)
        layout.addRow("Username:", self.ssh_user_input)
        layout.addRow("Auth Method:", auth_layout)
        layout.addRow("Password:", self.ssh_pass_input)
        layout.addRow("Private Key:", key_layout)
        layout.addRow("Remote Path:", self.ssh_remote_path_input)
        return widget

    def create_cloud_share_tab(self) -> QWidget:
        """Creates the 'Cloud Share (SaaS)' tab content (e.g., Google Drive)."""
        widget = QWidget()
        layout = QFormLayout(widget)
        self.gdrive_url_input = QLineEdit()
        self.gdrive_url_input.setPlaceholderText("Paste a public Google Drive file link here...")
        layout.addRow(QLabel("Google Drive URL:"), self.gdrive_url_input)
        return widget

    def create_container_share_tab(self) -> QWidget:
        """Creates the 'Container Share (CaaS)' tab content (e.g., Docker)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        container_layout = QHBoxLayout()
        self.docker_container_combo = QComboBox()
        self.docker_refresh_button = QPushButton("Refresh")
        container_layout.addWidget(QLabel("Running Container:"))
        container_layout.addWidget(self.docker_container_combo, 1) # Stretch the combobox
        container_layout.addWidget(self.docker_refresh_button)
        
        self.docker_volumes_tree = QTreeWidget()
        self.docker_volumes_tree.setHeaderLabels(["Container Paths (Select one to share)"])
        
        layout.addLayout(container_layout)
        layout.addWidget(self.docker_volumes_tree)
        
        self.docker_refresh_button.clicked.connect(self.refresh_docker_containers)
        # Connect itemClicked to enable start button only when a path is selected
        self.docker_volumes_tree.itemClicked.connect(lambda item, column: self.start_button.setEnabled(item is not None))
        self.docker_container_combo.currentIndexChanged.connect(self.on_docker_container_selected)
        
        self.refresh_docker_containers() # Populate initial list when tab is created
        return widget

    def create_paas_deploy_tab(self) -> QWidget:
        """Creates the 'Deploy to PaaS' tab content."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        provider_layout = QHBoxLayout()
        self.paas_provider_combo = QComboBox()
        self.paas_provider_combo.addItems(["Netlify", "Vercel"])
        provider_layout.addWidget(QLabel("PaaS Provider:"))
        provider_layout.addWidget(self.paas_provider_combo)
        provider_layout.addStretch()

        self.paas_stacked_widget = QStackedWidget()
        self.paas_stacked_widget.addWidget(self.create_netlify_ui()) # Index 0
        self.paas_stacked_widget.addWidget(self.create_vercel_ui())   # Index 1

        layout.addLayout(provider_layout)
        layout.addWidget(self.paas_stacked_widget)

        # Connect combo box to switch stacked widget pages
        self.paas_provider_combo.currentIndexChanged.connect(self.paas_stacked_widget.setCurrentIndex)
        self.paas_provider_combo.currentIndexChanged.connect(self.on_paas_provider_changed)

        return widget

    def create_netlify_ui(self) -> QWidget:
        """Creates the Netlify-specific input fields."""
        widget = QWidget()
        layout = QFormLayout(widget)
        layout.setContentsMargins(0, 10, 0, 0) # Adjust margins for better appearance within stacked widget
        
        self.netlify_token_input = QLineEdit()
        self.netlify_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.netlify_token_input.setPlaceholderText("Paste your Netlify Personal Access Token here")
        
        folder_layout = QHBoxLayout()
        self.netlify_folder_input = QLineEdit()
        browse_button = QPushButton("Browse...")
        folder_layout.addWidget(self.netlify_folder_input)
        folder_layout.addWidget(browse_button)
        
        layout.addRow("Netlify Access Token:", self.netlify_token_input)
        layout.addRow("Project Folder:", folder_layout)
        
        browse_button.clicked.connect(lambda: self.browse_project_folder(self.netlify_folder_input))
        return widget

    def create_vercel_ui(self) -> QWidget:
        """Creates the Vercel-specific input fields."""
        widget = QWidget()
        layout = QFormLayout(widget)
        layout.setContentsMargins(0, 10, 0, 0) # Adjust margins
        
        folder_layout = QHBoxLayout()
        self.vercel_folder_input = QLineEdit()
        browse_button = QPushButton("Browse...")
        folder_layout.addWidget(self.vercel_folder_input)
        folder_layout.addWidget(browse_button)
        
        layout.addRow("Project Folder:", folder_layout)
        
        browse_button.clicked.connect(lambda: self.browse_project_folder(self.vercel_folder_input))
        return widget

    def browse_local_path(self):
        """Opens a file dialog to select a local file or folder."""
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.FileMode.AnyFile) # Allows selection of files or directories
        dialog.setOption(QFileDialog.Option.ShowDirsOnly, False) # Show files too

        # For selecting both file and folder:
        # A common trick is to use getExistingDirectory for folders, getOpenFileName for files
        # Or, manually check if the selected path is a file or directory after dialog.exec()
        
        # This will open a dialog that allows selecting files. If a directory is intended,
        # you might want getExistingDirectory. For simplicity for "Anything Online", AnyFile is ok.
        
        if dialog.exec():
            selected_path = dialog.selectedFiles()[0]
            self.local_path_input.setText(selected_path)
            self.log(f"Selected path: {selected_path}")

    def browse_project_folder(self, target_line_edit: QLineEdit):
        """Opens a directory dialog and sets the selected path to the target QLineEdit."""
        folder = QFileDialog.getExistingDirectory(self, "Select Project Folder")
        if folder:
            target_line_edit.setText(folder)
            self.log(f"Selected project folder: {folder}")

    def on_auth_toggled(self, checked: bool):
        """Enables/disables username/password inputs based on checkbox state."""
        self.user_input.setEnabled(checked)
        self.pass_input.setEnabled(checked)
        self.user_label.setVisible(checked)
        self.pass_label.setVisible(checked)

    def on_main_tab_changed(self, index: int):
        """Adjusts UI elements based on the currently selected main tab."""
        current_tab_name = self.tab_widget.tabText(index)
        is_deploy_tab = current_tab_name == "Deploy to PaaS"

        # Hide/show shared tunnel controls for PaaS tab
        for widget in [self.service_label, self.service_combo, self.port_label, self.port_spinner,
                       self.auth_checkbox, self.user_input, self.pass_input, self.user_label, self.pass_label]:
            widget.setVisible(not is_deploy_tab)

        if is_deploy_tab:
            # If on deploy tab, set button text to "Deploy" and trigger PaaS-specific UI update
            self.on_paas_provider_changed()
        else:
            # If not on deploy tab, set button text back to "Start Tunnel"
            self.start_button.setText("Start Tunnel")
            # Re-apply auth checkbox state as its visibility changed
            self.on_auth_toggled(self.auth_checkbox.isChecked())
            
        # Ensure start button is enabled/disabled based on current tab's content validity
        # This is a simplified logic, detailed validation should happen in start_action
        if is_deploy_tab:
            # For deploy tab, enable start button by default, specific validation happens on click
            self.start_button.setEnabled(True) 
        elif current_tab_name == "Container Share (CaaS)":
            # For container share, enable only if an item is selected in the tree
            self.start_button.setEnabled(self.docker_volumes_tree.currentItem() is not None)
        else:
            # For other tabs, enable by default assuming basic input is met
            self.start_button.setEnabled(True)

    def on_paas_provider_changed(self):
        """Updates the start button text based on the selected PaaS provider."""
        provider_name = self.paas_provider_combo.currentText()
        self.start_button.setText(f"Deploy to {provider_name}")

    def log(self, message: str):
        """Appends a message to the status output text edit."""
        self.status_output.append(str(message))
        # Auto-scroll to the bottom
        self.status_output.verticalScrollBar().setValue(self.status_output.verticalScrollBar().maximum())

    def log_and_reset(self, message: str):
        """Logs an error message and then resets the UI state."""
        self.log(f"Error: {message}")
        self.reset_ui()

    def set_ui_enabled(self, enabled: bool):
        """Enables or disables relevant UI elements based on operation state."""
        self.tab_widget.setEnabled(enabled)
        # self.start_button.setEnabled(enabled) # This is handled by specific tab logic now
        self.stop_button.setEnabled(not enabled)
        
        # When enabling UI, re-evaluate start button state based on current tab
        if enabled:
            self.on_main_tab_changed(self.tab_widget.currentIndex())

    def reset_ui(self):
        """Resets the UI to its initial interactive state."""
        self.set_ui_enabled(True)
        self.log("Ready.")

    def start_action(self):
        """Determines the action to take based on the current tab and initiates it."""
        self.log("Starting action...")
        self.set_ui_enabled(False) # Disable UI elements to prevent new actions while busy

        current_tab_index = self.tab_widget.currentIndex()
        current_tab_text = self.tab_widget.tabText(current_tab_index)

        if current_tab_text == "Local Share":
            self._start_local_share()
        elif current_tab_text == "Remote Share (SFTP)":
            self._start_sftp_download()
        elif current_tab_text == "Cloud Share (SaaS)":
            self._start_gdrive_download()
        elif current_tab_text == "Container Share (CaaS)":
            self._start_docker_copy()
        elif current_tab_text == "Deploy to PaaS":
            self._start_paas_deploy()
        else:
            self.log_and_reset("Unknown tab selected.")

    def _start_local_share(self):
        """Starts the local web server and chosen tunnel service."""
        directory = self.local_path_input.text()
        if not directory:
            self.log_and_reset("Please select a local file or folder to share.")
            return
        if not os.path.exists(directory):
            self.log_and_reset(f"Error: The selected path '{directory}' does not exist.")
            return
        
        port = self.port_spinner.value()
        username = self.user_input.text() if self.auth_checkbox.isChecked() else None
        password = self.pass_input.text() if self.auth_checkbox.isChecked() else None

        # --- Web Server Setup ---
        self.web_server_worker = WebServerWorker(directory, port, username, password)
        self.web_server_thread = QThread()
        self.web_server_worker.moveToThread(self.web_server_thread)
        
        self.web_server_thread.started.connect(self.web_server_worker.run)
        self.web_server_worker.server_started.connect(self.on_web_server_started)
        self.web_server_worker.error_received.connect(self.log_and_reset)
        
        # Connect finished signal to quit thread and delete worker/thread objects
        self.web_server_worker.finished.connect(self.web_server_thread.quit)
        self.web_server_worker.finished.connect(self.web_server_worker.deleteLater)
        self.web_server_thread.finished.connect(self.web_server_thread.deleteLater)

        self.web_server_thread.start()
        self.log(f"Starting local web server on port {port} for: '{directory}'")

        # --- Tunnel Setup ---
        selected_tunnel_service = self.service_combo.currentText()
        TunnelWorkerClass = self.tunnel_worker_map.get(selected_tunnel_service)
        
        if TunnelWorkerClass:
            self.tunnel_worker = TunnelWorkerClass(port)
            self.tunnel_thread = QThread()
            self.tunnel_worker.moveToThread(self.tunnel_thread)
            
            self.tunnel_thread.started.connect(self.tunnel_worker.run)
            self.tunnel_worker.url_received.connect(self.on_tunnel_url_received)
            self.tunnel_worker.error_received.connect(self.log_and_reset)
            if hasattr(self.tunnel_worker, 'log_message'): # For workers with extra logging
                self.tunnel_worker.log_message.connect(self.log)

            # Connect finished signal to quit thread and delete worker/thread objects
            self.tunnel_worker.finished.connect(self.tunnel_thread.quit)
            self.tunnel_worker.finished.connect(self.tunnel_worker.deleteLater)
            self.tunnel_thread.finished.connect(self.tunnel_thread.deleteLater)
            
            self.tunnel_thread.start()
            self.log(f"Starting {selected_tunnel_service} tunnel...")
        else:
            self.log_and_reset("Invalid tunnel service selected. Stopping web server.")
            self.stop_all_workers_and_threads() # Ensure web server is also stopped

    def _start_sftp_download(self):
        """Initiates an SFTP file/folder download."""
        host = self.ssh_host_input.text().strip()
        port = self.ssh_port_spinner.value()
        user = self.ssh_user_input.text().strip()
        remote_path = self.ssh_remote_path_input.text().strip()
        
        password = self.ssh_pass_input.text() if self.auth_pass_radio.isChecked() else None
        pkey_path = self.ssh_key_path_input.text() if self.auth_key_radio.isChecked() else None

        if not all([host, user, remote_path]):
            self.log_and_reset("Please fill in Host, Username, and Remote Path for SFTP.")
            return
        if self.auth_pass_radio.isChecked() and not password:
            self.log_and_reset("Please enter a password for SFTP authentication.")
            return
        if self.auth_key_radio.isChecked() and (not pkey_path or not os.path.exists(pkey_path)):
            self.log_and_reset("Please select a valid private key file for SFTP authentication.")
            return

        worker = SftpDownloadWorker(host, port, user, password, pkey_path, remote_path)
        thread = QThread()
        worker.moveToThread(thread)
        
        thread.started.connect(worker.run)
        worker.finished.connect(lambda path: self.on_data_source_downloaded(path, "SFTP"))
        worker.error_received.connect(self.log_and_reset)
        worker.log_message.connect(self.log) # Connect log message for progress
        
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        
        self._one_shot_threads.append((thread, worker)) # Add to cleanup list
        thread.start()
        self.log(f"Initiating SFTP download from {host}:{port}{remote_path}...")

    def _start_gdrive_download(self):
        """Initiates a Google Drive file download."""
        url = self.gdrive_url_input.text().strip()
        if not url:
            self.log_and_reset("Please enter a Google Drive URL.")
            return

        worker = GdriveDownloadWorker(url)
        thread = QThread()
        worker.moveToThread(thread)
        
        thread.started.connect(worker.run)
        worker.finished.connect(lambda path: self.on_data_source_downloaded(path, "G-Drive"))
        worker.error_received.connect(self.log_and_reset)
        worker.log_message.connect(self.log) # Connect log_message signal for progress
        
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        
        self._one_shot_threads.append((thread, worker))
        thread.start()
        self.log(f"Initiating Google Drive download for {url}...")

    def _start_docker_copy(self):
        """Initiates copying data from a Docker container."""
        selected_container_text = self.docker_container_combo.currentText()
        selected_item = self.docker_volumes_tree.currentItem()

        if not selected_container_text:
            self.log_and_reset("No Docker container selected.")
            return
        if not selected_item:
            self.log_and_reset("No path selected in the Docker container.")
            return
        
        try:
            # Extract container ID from the combo box text (e.g., "name (ID)")
            container_id_match = re.search(r'\(([a-f0-9]+)\)', selected_container_text)
            if not container_id_match:
                self.log_and_reset("Could not extract container ID. Please refresh Docker list.")
                return
            container_id = container_id_match.group(1)
            container_path = selected_item.text(0).strip() # Get the path from the tree item

            if not container_path:
                self.log_and_reset("Selected Docker path is empty.")
                return

            worker = DockerCopyWorker(container_id, container_path)
            thread = QThread()
            worker.moveToThread(thread)
            
            thread.started.connect(worker.run)
            worker.finished.connect(lambda path: self.on_data_source_downloaded(path, f"Docker ({container_path})"))
            worker.error_received.connect(self.log_and_reset)
            worker.log_message.connect(self.log) # Connect log message
            
            worker.finished.connect(thread.quit)
            worker.finished.connect(worker.deleteLater)
            thread.finished.connect(thread.deleteLater)
            
            self._one_shot_threads.append((thread, worker))
            thread.start()
            self.log(f"Initiating Docker copy from container '{selected_container_text}' path '{container_path}'...")
        
        except Exception as e:
            self.log_and_reset(f"Error preparing Docker copy: {e}")


    def _start_paas_deploy(self):
        """Initiates deployment to the selected PaaS provider."""
        provider = self.paas_provider_combo.currentText()
        worker = None
        
        if provider == "Netlify":
            token = self.netlify_token_input.text().strip()
            folder_path = self.netlify_folder_input.text().strip()
            if not token:
                self.log_and_reset("Please provide a Netlify Access Token.")
                return
            if not folder_path or not os.path.isdir(folder_path):
                self.log_and_reset("Please provide a valid project folder for Netlify.")
                return
            worker = NetlifyDeployWorker(token, folder_path)
        elif provider == "Vercel":
            folder_path = self.vercel_folder_input.text().strip()
            if not folder_path or not os.path.isdir(folder_path):
                self.log_and_reset("Please provide a valid project folder for Vercel.")
                return
            worker = VercelDeployWorker(folder_path)
        else:
            self.log_and_reset("Unknown PaaS provider selected.")
            return

        thread = QThread()
        worker.moveToThread(thread)
        
        thread.started.connect(worker.run)
        worker.finished.connect(lambda url: self.on_paas_deployed(url, provider))
        worker.error_received.connect(self.log_and_reset)
        worker.log_message.connect(self.log) # Connect log message for CLI output
        
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        
        self._one_shot_threads.append((thread, worker))
        thread.start()
        self.log(f"Initiating deployment to {provider}...")

    def on_web_server_started(self, host: str, port: int):
        """Callback when the local web server starts."""
        self.log(f"Web server started at http://{host}:{port}")

    def on_tunnel_url_received(self, url: str):
        """Callback when the tunnel URL is received."""
        self.log(f"Tunnel URL: {url}")
        self.stop_button.setEnabled(True) # Enable stop button once services are fully running

    def on_data_source_downloaded(self, path: str, source_type: str):
        """Callback when data source download is complete."""
        self.log(f"'{source_type}' data download complete. Data available locally at: {path}")
        self.temp_dir_path = path # Store this path for eventual cleanup
        self.reset_ui() # Reset UI, enabling buttons again

    def on_paas_deployed(self, url: str, provider: str):
        """Callback when PaaS deployment is complete."""
        self.log(f"Deployment to {provider} successful. Public URL: {url}")
        self.reset_ui() # Reset UI, enabling buttons again

    def refresh_docker_containers(self):
        """Refreshes the list of running Docker containers."""
        self.log("Refreshing Docker containers...")
        self.docker_container_combo.clear()
        self.docker_volumes_tree.clear()
        self.start_button.setEnabled(False) # Disable start button until a valid path is selected

        worker = DockerListContainersWorker()
        thread = QThread()
        worker.moveToThread(thread)
        
        thread.started.connect(worker.run)
        worker.finished.connect(self.on_docker_containers_listed)
        worker.error_received.connect(self.log) # Log errors, but don't reset UI completely for just refresh
        worker.log_message.connect(self.log) # Connect log message for progress
        
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        
        self._one_shot_threads.append((thread, worker)) # Treat this refresh as a one-shot operation
        thread.start()

    def on_docker_containers_listed(self, containers: list):
        """Callback after Docker containers have been listed."""
        if not containers:
            self.log("No running Docker containers found.")
            return

        self.docker_container_combo.clear()
        for container in containers:
            # Display name and a truncated ID for clarity
            self.docker_container_combo.addItem(f"{container.name} ({container.id[:12]})")
        
        self.log(f"Found {len(containers)} running Docker containers. Select one to list paths.")
        if containers:
            # Trigger selection changed for the first item to populate paths immediately
            self.on_docker_container_selected(0) 
        else:
            self.docker_volumes_tree.clear() # Ensure tree is empty if no containers

    def on_docker_container_selected(self, index: int):
        """Populates the Docker paths tree for the selected container."""
        self.docker_volumes_tree.clear()
        self.start_button.setEnabled(False) # Disable start button until a path is explicitly selected

        if index < 0 or self.docker_container_combo.count() == 0:
            return

        selected_text = self.docker_container_combo.currentText()
        if not selected_text:
            return

        try:
            # Extract container ID from "name (ID)" format
            container_id_match = re.search(r'\(([a-f0-9]+)\)', selected_text)
            if not container_id_match:
                self.log(f"Could not parse container ID from '{selected_text}'.")
                return
            container_id = container_id_match.group(1)
            
            client = docker.from_env()
            container = client.containers.get(container_id)
            
            self.log(f"Inspecting container '{container.name}' for shareable paths...")

            # --- Simplified approach for listing paths ---
            # Listing ALL files in a Docker container can be extremely slow and resource-intensive.
            # A common approach is to list well-known paths (e.g., /app, /var/www, /)
            # or to list explicit volumes. Docker SDK's `exec_run` can be used to run `ls` commands.
            
            # Add root directory as a selectable item
            root_item = QTreeWidgetItem(["/"])
            self.docker_volumes_tree.addTopLevelItem(root_item)

            # Attempt to list contents of common web server directories if they exist
            common_web_paths = ["/var/www/html", "/usr/share/nginx/html", "/app", "/usr/src/app"]
            for path in common_web_paths:
                try:
                    # Use exec_run to check if path is a directory
                    # `ls -d` lists the directory itself, not its contents
                    # `test -d` is more efficient for just checking existence
                    exit_code, output = container.exec_run(f"test -d {path}")
                    if exit_code == 0: # If it's a directory
                        item = QTreeWidgetItem([path])
                        self.docker_volumes_tree.addTopLevelItem(item)
                        self.log(f"Found common path: {path}")
                    else:
                        self.log(f"Path '{path}' not found or not a directory in container '{container.name}'.")
                except Exception as e:
                    self.log(f"Warning: Could not check path '{path}' in container '{container.name}': {e}")
            
            self.log("Done listing potential share paths. Click on an item in the tree to select it.")

        except docker.errors.DockerException as e:
            self.log(f"Docker error: Could not connect to Docker daemon or get container details. Is Docker running? Details: {e}")
        except Exception as e:
            self.log(f"An unexpected error occurred while listing container paths: {e}")

    def stop_action(self):
        """Initiates stopping of all active services."""
        self.log("Stopping all active services...")
        self.stop_all_workers_and_threads()
        self.reset_ui()
        self.log("All services stopped. UI reset.")
    
    def stop_all_workers_and_threads(self):
        """
        Stops all running workers (web server, tunnel, one-shot tasks) and
        cleans up their associated threads and temporary directories.
        """
        # --- Stop Web Server ---
        if self.web_server_worker and self.web_server_thread and self.web_server_thread.isRunning():
            self.log("Signaling web server to stop...")
            self.web_server_worker.stop() # Call worker's stop method
            self.web_server_thread.quit() # Signal QThread's event loop to quit
            self.web_server_thread.wait(5000) # Wait up to 5 seconds for thread to finish
            if self.web_server_thread.isRunning():
                self.log("Web server thread did not terminate gracefully within timeout.")
            self.web_server_worker = None
            self.web_server_thread = None
            self.log("Web server cleanup complete.")

        # --- Stop Tunnel ---
        if self.tunnel_worker and self.tunnel_thread and self.tunnel_thread.isRunning():
            self.log("Signaling tunnel to stop...")
            self.tunnel_worker.stop() # Call worker's stop method (terminates subprocess)
            self.tunnel_thread.quit() # Signal QThread's event loop to quit
            self.tunnel_thread.wait(5000) # Wait up to 5 seconds for thread to finish
            if self.tunnel_thread.isRunning():
                self.log("Tunnel thread did not terminate gracefully within timeout.")
            self.tunnel_worker = None
            self.tunnel_thread = None
            self.log("Tunnel cleanup complete.")

        # --- Stop and Clean Up One-Shot Threads ---
        # Iterate in reverse to allow removal if needed, though deleteLater handles it.
        threads_to_clear = [] 
        for thread, worker in list(self._one_shot_threads): # Iterate over a copy
            if thread.isRunning():
                self.log(f"Stopping one-shot task '{worker.__class__.__name__}'...")
                if hasattr(worker, 'stop') and callable(worker.stop):
                    worker.stop() # Call worker's specific stop method if it exists
                thread.quit() # Signal QThread to quit
                thread.wait(5000) # Wait for thread to finish
                if thread.isRunning():
                    self.log(f"One-shot task '{worker.__class__.__name__}' thread did not terminate gracefully.")
            
            # Mark for cleanup (deleteLater schedules deletion, doesn't delete immediately)
            worker.deleteLater()
            thread.deleteLater()
            threads_to_clear.append((thread, worker))
            
        # Remove stopped threads from the list
        for item in threads_to_clear:
            if item in self._one_shot_threads:
                self._one_shot_threads.remove(item)
        self._one_shot_threads.clear() # Ensure the list is fully cleared

        self.log("One-shot tasks cleanup complete.")

        # --- Clean up Temporary Directory ---
        if self.temp_dir_path and os.path.exists(self.temp_dir_path):
            self.log(f"Cleaning up temporary directory: '{self.temp_dir_path}'...")
            try:
                # Ensure the directory is empty or accessible before trying to remove
                # Sometimes permissions or open handles can cause issues
                shutil.rmtree(self.temp_dir_path, ignore_errors=True) # ignore_errors might hide issues but prevent crash
                if os.path.exists(self.temp_dir_path): # Check if it's actually gone
                     self.log(f"Warning: Temporary directory '{self.temp_dir_path}' still exists after cleanup attempt.")
                else:
                    self.log("Temporary directory cleaned up.")
            except OSError as e:
                self.log(f"Error cleaning up temporary directory '{self.temp_dir_path}': {e}")
            self.temp_dir_path = None # Clear reference after attempting cleanup
        else:
            self.log("No temporary directories to clean up.")
    
    # Override closeEvent to ensure all threads are stopped when the app closes
    def closeEvent(self, event):
        """
        Handles the application close event, ensuring all background processes
        and threads are properly terminated before the application exits.
        """
        self.log("Application closing. Initiating graceful shutdown of all services...")
        self.stop_all_workers_and_threads()
        self.log("All services shut down. Application can now close.")
        event.accept() # Accept the close event, allowing the application to exit


if __name__ == '__main__':
    # Ensure QApplication is initialized once
    app = QApplication(sys.argv)
    
    # Create and show the main window
    main_window = MainWindow()
    main_window.show()
    
    # Start the application event loop
    sys.exit(app.exec())