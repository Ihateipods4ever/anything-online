# Standard library imports
import base64
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

# --- Optional Dependency Imports ---
# These are handled as optional and will be set to None if not found.
# The application will provide feedback to the user if they are needed.
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
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="Restricted Area"')
                    self.end_headers()
                    return False
                try:
                    auth_type, encoded_creds = auth_header.split(' ', 1)
                    if auth_type.lower() != 'basic': raise ValueError("Not Basic Auth")
                    decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                    user, passw = decoded_creds.split(':', 1)
                except Exception:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="Invalid Header"')
                    self.end_headers()
                    return False
                if user == self._auth_user and passw == self._auth_pass:
                    return True
                else:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="Incorrect Credentials"')
                    self.end_headers()
                    return False

            def do_GET(self):
                if self.do_auth():
                    super().do_GET()

        try:
            self.httpd = HTTPServer(("", self.port), AuthHandler)
            host, port = self.httpd.socket.getsockname()
            self.server_started.emit(host, port)
            self.httpd.serve_forever()
        except OSError as e:
            self.error_received.emit(f"Web server error: {e}. The port might be in use.")
        except Exception as e:
            self.error_received.emit(f"An unexpected web server error occurred: {e}")
        finally:
            self.finished.emit()

    def stop(self):
        if self.httpd:
            threading.Thread(target=self.httpd.shutdown).start()

# --- Tunneling Service Workers ---
class BaseTunnelWorker(QObject):
    finished = pyqtSignal()
    url_received = pyqtSignal(str)
    error_received = pyqtSignal(str)

    def __init__(self, port):
        super().__init__()
        self.port = port
        self.process = None
        self._is_running = True

    def get_command(self):
        raise NotImplementedError("Subclasses must implement get_command")

    def parse_url(self, line):
        raise NotImplementedError("Subclasses must implement parse_url")

    def get_executable_name(self):
        return self.get_command()[0]

    def get_not_found_error(self):
        return f"Error: '{self.get_executable_name()}' executable not found."

    def run(self):
        command = self.get_command()
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            for line in iter(self.process.stdout.readline, ''):
                if not self._is_running:
                    break
                url = self.parse_url(line)
                if url:
                    self.url_received.emit(url)
            self.process.wait()
        except FileNotFoundError:
            self.error_received.emit(self.get_not_found_error())
        except Exception as e:
            self.error_received.emit(f"{self.get_executable_name()} error: {e}")
        self.finished.emit()

    def stop(self):
        self._is_running = False
        if self.process:
            self.process.terminate()

class NgrokTunnelWorker(BaseTunnelWorker):
    def get_command(self): return ["ngrok", "http", str(self.port), "--log=stdout"]
    def parse_url(self, line):
        if "url=" in line:
            try: return line.split("url=")[1].strip()
            except IndexError: return None
    def get_not_found_error(self):
        return "Error: 'ngrok' not found. Please download it from https://ngrok.com/download and place it in your PATH."

class CloudflareTunnelWorker(BaseTunnelWorker):
    def get_command(self): return ["cloudflared", "tunnel", "--url", f"http://localhost:{self.port}", "--no-autoupdate"]
    def parse_url(self, line):
        if "trycloudflare.com" in line and "INF" in line:
            try:
                for part in line.split():
                    if part.startswith("https://") and "trycloudflare.com" in part: return part
            except Exception: return None
    def get_not_found_error(self):
        return "Error: 'cloudflared' not found. Please see installation instructions at https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/"

class LocalTunnelWorker(BaseTunnelWorker):
    def get_command(self): return ["lt", "--port", str(self.port)]
    def parse_url(self, line):
        if "your url is:" in line:
            try: return line.split("your url is:")[1].strip()
            except IndexError: return None
    def get_not_found_error(self): return "Error: 'lt' not found. Run 'npm install -g localtunnel'."

class ServeoWorker(BaseTunnelWorker):
    def get_command(self):
        # Use -tt to force pseudo-terminal allocation. This is often necessary
        # for services like Serveo that expect an interactive-like session to
        # start properly, preventing the ssh client from exiting immediately.
        # Use os.devnull for cross-platform compatibility (Windows vs. Unix).
        return [
            "ssh", "-tt",
            "-R", f"80:localhost:{self.port}",
            "-o", "StrictHostKeyChecking=no",
            "-o", f"UserKnownHostsFile={os.devnull}",
            "serveo.net"
        ]
    def parse_url(self, line):
        # The -tt option can add terminal escape codes. A regex is more robust.
        # Example: "Forwarding HTTP traffic from \x1b[1;32mhttps://random.serveo.net\x1b[0m"
        match = re.search(r'(https://[a-zA-Z0-9-]+\.serveo\.net)', line)
        return match.group(1) if match else None
    def get_executable_name(self): return "ssh"

# --- Data Source Workers (SSH, Cloud, Docker) ---
class SftpDownloadWorker(QObject):
    finished, error_received = pyqtSignal(str), pyqtSignal(str)
    def __init__(self, host, port, user, password, pkey_path, remote_path):
        super().__init__(); self.host, self.port, self.user, self.password, self.pkey_path, self.remote_path = host, port, user, password, pkey_path, remote_path
    def run(self):
        if not paramiko:
            self.error_received.emit("SFTP download failed: 'paramiko' library not found. Please run 'pip install paramiko'.")
            return
        try:
            temp_dir = tempfile.mkdtemp(prefix="ssh_")
            client = paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            pkey = paramiko.RSAKey.from_private_key_file(self.pkey_path) if self.pkey_path else None
            client.connect(hostname=self.host, port=self.port, username=self.user, password=self.password or None, pkey=pkey, timeout=10)
            sftp = client.open_sftp()
            if stat.S_ISDIR(sftp.stat(self.remote_path).st_mode):
                for item in sftp.listdir(self.remote_path):
                    remote_item_path = os.path.join(self.remote_path, item).replace("\\", "/")
                    local_item_path = os.path.join(temp_dir, item)
                    sftp.get(remote_item_path, local_item_path)
            else:
                sftp.get(self.remote_path, os.path.join(temp_dir, os.path.basename(self.remote_path)))
            sftp.close(); client.close()
            self.finished.emit(temp_dir)
        except Exception as e: self.error_received.emit(f"SSH/SFTP Error: {e}")

class DockerListContainersWorker(QObject):
    """Lists running Docker containers."""
    finished = pyqtSignal(list)
    error_received = pyqtSignal(str)

    def run(self):
        if not docker:
            self.error_received.emit("Docker SDK not installed. Please run 'pip install docker'.")
            return
        try:
            client = docker.from_env()
            containers = client.containers.list()
            self.finished.emit(containers)
        except docker.errors.DockerException as e:
            self.error_received.emit(f"Docker error: Could not connect to Docker daemon. Is it running?")
        except Exception as e:
            self.error_received.emit(f"An unexpected Docker error occurred: {e}")


class DockerCopyWorker(QObject):
    finished, error_received = pyqtSignal(str), pyqtSignal(str)
    def __init__(self, container_id, container_path):
        super().__init__(); self.container_id, self.container_path = container_id, container_path
    def run(self):
        if not docker:
            self.error_received.emit("Docker copy failed: 'docker' library not found. Please run 'pip install docker'.")
            return
        try:
            client = docker.from_env(); container = client.containers.get(self.container_id)
            temp_dir = tempfile.mkdtemp(prefix="docker_")
            bits, stat = container.get_archive(self.container_path)
            with io.BytesIO() as tar_buffer:
                for chunk in bits: tar_buffer.write(chunk)
                tar_buffer.seek(0)
                with tarfile.open(fileobj=tar_buffer) as tar: tar.extractall(path=temp_dir)
            self.finished.emit(os.path.join(temp_dir, os.path.basename(self.container_path)))
        except Exception as e: self.error_received.emit(f"Docker copy error: {e}")

# --- PaaS Deployment Workers ---
class NetlifyDeployWorker(QObject):
    finished, error_received, log_message = pyqtSignal(str), pyqtSignal(str), pyqtSignal(str)
    def __init__(self, token, folder_path):
        super().__init__(); self.token, self.folder_path = token, folder_path
    def run(self):
        if not requests:
            self.error_received.emit("Netlify deployment failed: 'requests' library not found. Please run 'pip install requests'.")
            return
        try:
            self.log_message.emit("Zipping project folder...")
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(self.folder_path):
                    for file in files: zf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), self.folder_path))
            zip_buffer.seek(0)
            self.log_message.emit("Uploading to Netlify...")
            headers = {'Content-Type': 'application/zip', 'Authorization': f'Bearer {self.token}'}
            response = requests.post('https://api.netlify.com/api/v1/sites', headers=headers, data=zip_buffer.read())
            response.raise_for_status()
            self.finished.emit(response.json()['url'])
        except Exception as e: self.error_received.emit(f"Netlify deployment failed: {e}")

class VercelDeployWorker(QObject):
    finished, error_received, log_message = pyqtSignal(str), pyqtSignal(str), pyqtSignal(str)
    def __init__(self, folder_path):
        super().__init__(); self.folder_path = folder_path
    def run(self):
        try:
            self.log_message.emit("Deploying to Vercel via CLI...")
            command = ["vercel", "--prod", "--yes"]
            process = subprocess.Popen(command, cwd=self.folder_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
            url_found = False
            for line in iter(process.stdout.readline, ''):
                self.log_message.emit(line.strip())
                if "Production:" in line:
                    url = line.split("Production:")[1].strip().split(" ")[0]
                    self.finished.emit(url); url_found = True
            if not url_found: self.error_received.emit("Could not find production URL in Vercel CLI output.")
        except FileNotFoundError: self.error_received.emit("Vercel CLI not found. Please run 'npm i -g vercel' and log in.")
        except Exception as e: self.error_received.emit(f"Vercel deployment failed: {e}")

# --- Main Application Window ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Universal Tunneling & Deployment GUI")
        # The setGeometry call can sometimes produce a harmless "window move completed without beginning"
        # warning on some platforms (like macOS). By only setting the size and letting the
        # window manager decide the initial position, we can often avoid this message.
        self.resize(800, 600)

        self.web_server_thread, self.tunnel_thread, self.data_worker_thread, self.paas_thread = None, None, None, None
        self.web_server_worker, self.tunnel_worker, self.data_worker, self.paas_worker = None, None, None, None
        self.temp_dir_path = None
        self.tunnel_worker_map = {
            "ngrok": NgrokTunnelWorker,
            "Cloudflare Tunnel": CloudflareTunnelWorker,
            "localtunnel": LocalTunnelWorker,
            "Serveo": ServeoWorker
        }

        main_widget = QWidget(); self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        # Status/Log output (must be created before tabs that might log messages on init)
        self.status_output = QTextEdit(); self.status_output.setReadOnly(True)

        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # --- Create Tabs ---
        self.tab_widget.addTab(self.create_local_share_tab(), "Local Share")
        self.tab_widget.addTab(self.create_remote_share_tab(), "Remote Share (SSH)")
        self.tab_widget.addTab(self.create_cloud_share_tab(), "Cloud Share (SaaS)")
        self.tab_widget.addTab(self.create_container_share_tab(), "Container Share (CaaS)")
        self.tab_widget.addTab(self.create_paas_deploy_tab(), "Deploy to PaaS")

        # --- Shared Controls ---
        shared_controls_layout = QVBoxLayout()
        layout.addLayout(shared_controls_layout)
        
        # Tunneling Service
        service_layout = QHBoxLayout()
        self.service_combo = QComboBox()
        self.service_combo.addItems(self.tunnel_worker_map.keys())
        service_layout.addWidget(QLabel("Tunnel Service:"))
        service_layout.addWidget(self.service_combo)
        service_layout.addStretch()

        # Port selection
        port_layout = QHBoxLayout()
        self.port_spinner = QSpinBox()
        self.port_spinner.setRange(1024, 65535); self.port_spinner.setValue(8000)
        port_layout.addWidget(QLabel("Local Port:"))
        port_layout.addWidget(self.port_spinner)
        port_layout.addStretch()

        # Authentication section
        auth_form_layout = QFormLayout()
        self.auth_checkbox = QCheckBox("Enable Password Protection")
        self.user_input = QLineEdit(); self.user_input.setPlaceholderText("Username"); self.user_input.setEnabled(False)
        self.pass_input = QLineEdit(); self.pass_input.setPlaceholderText("Password"); self.pass_input.setEchoMode(QLineEdit.EchoMode.Password); self.pass_input.setEnabled(False)
        auth_form_layout.addRow(self.auth_checkbox)
        auth_form_layout.addRow("Username:", self.user_input)
        auth_form_layout.addRow("Password:", self.pass_input)

        # Control buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Tunnel")
        self.stop_button = QPushButton("Stop All"); self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button); button_layout.addWidget(self.stop_button); button_layout.addStretch()

        shared_controls_layout.addLayout(service_layout)
        shared_controls_layout.addLayout(port_layout)
        shared_controls_layout.addLayout(auth_form_layout)
        shared_controls_layout.addLayout(button_layout)
        layout.addWidget(QLabel("Logs & Status:"))
        layout.addWidget(self.status_output)

        # --- Connect Signals ---
        self.start_button.clicked.connect(self.start_action)
        self.stop_button.clicked.connect(self.stop_all_services)
        self.auth_checkbox.toggled.connect(lambda c: [w.setEnabled(c) for w in [self.user_input, self.pass_input]])
        self.tab_widget.currentChanged.connect(self.on_main_tab_changed)
        self.on_main_tab_changed(0) # Set initial button text

    # --- UI Creation Methods ---
    def create_local_share_tab(self):
        widget = QWidget(); layout = QHBoxLayout(widget)
        self.local_path_input = QLineEdit(); self.local_path_input.setPlaceholderText("Select a local folder to share...")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(lambda: self.local_path_input.setText(QFileDialog.getExistingDirectory(self, "Select Folder")))
        layout.addWidget(QLabel("Folder Path:")); layout.addWidget(self.local_path_input); layout.addWidget(browse_button)
        return widget

    def create_remote_share_tab(self):
        widget = QWidget(); layout = QFormLayout(widget)
        self.ssh_host_input = QLineEdit(); self.ssh_port_spinner = QSpinBox(); self.ssh_port_spinner.setRange(1, 65535); self.ssh_port_spinner.setValue(22)
        self.ssh_user_input = QLineEdit(); self.ssh_remote_path_input = QLineEdit(); self.ssh_remote_path_input.setPlaceholderText("/home/user/share_folder")
        self.auth_pass_radio = QRadioButton("Password"); self.auth_key_radio = QRadioButton("Private Key"); self.auth_pass_radio.setChecked(True)
        auth_layout = QHBoxLayout(); auth_layout.addWidget(self.auth_pass_radio); auth_layout.addWidget(self.auth_key_radio)
        self.ssh_pass_input = QLineEdit(); self.ssh_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout = QHBoxLayout(); self.ssh_key_path_input = QLineEdit(); self.ssh_key_path_input.setPlaceholderText("Path to your private SSH key"); self.ssh_key_path_input.setEnabled(False)
        browse_key_button = QPushButton("Browse..."); browse_key_button.setEnabled(False)
        browse_key_button.clicked.connect(lambda: self.ssh_key_path_input.setText(QFileDialog.getOpenFileName(self, "Select Private Key")[0]))
        key_layout.addWidget(self.ssh_key_path_input); key_layout.addWidget(browse_key_button)
        self.auth_pass_radio.toggled.connect(lambda checked: [self.ssh_pass_input.setEnabled(checked), self.ssh_key_path_input.setEnabled(not checked), browse_key_button.setEnabled(not checked)])
        layout.addRow("Host:", self.ssh_host_input); layout.addRow("Port:", self.ssh_port_spinner); layout.addRow("Username:", self.ssh_user_input)
        layout.addRow("Auth Method:", auth_layout); layout.addRow("Password:", self.ssh_pass_input); layout.addRow("Private Key:", key_layout)
        layout.addRow("Remote Path:", self.ssh_remote_path_input)
        return widget

    def create_cloud_share_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        label = QLabel("Cloud provider integrations (Google Drive, Dropbox, etc.) were omitted for brevity.\nThis feature can be re-added.")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setWordWrap(True)
        layout.addWidget(label)
        widget.setEnabled(False) # Disable the whole tab
        return widget

    def create_container_share_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Container selection
        container_layout = QHBoxLayout()
        self.docker_container_combo = QComboBox()
        self.docker_refresh_button = QPushButton("Refresh")
        container_layout.addWidget(QLabel("Running Container:"))
        container_layout.addWidget(self.docker_container_combo, 1)
        container_layout.addWidget(self.docker_refresh_button)
        
        # Volumes/Paths Tree
        self.docker_volumes_tree = QTreeWidget()
        self.docker_volumes_tree.setHeaderLabels(["Container Paths (Select one to share)"])

        layout.addLayout(container_layout)
        layout.addWidget(self.docker_volumes_tree)

        # Connect signals
        self.docker_refresh_button.clicked.connect(self.refresh_docker_containers)
        self.docker_container_combo.currentIndexChanged.connect(self.on_docker_container_selected)
        
        # Initial population
        self.refresh_docker_containers()
        
        return widget

    def create_netlify_ui(self):
        widget = QWidget(); layout = QFormLayout(widget); layout.setContentsMargins(0, 10, 0, 0)
        self.netlify_token_input = QLineEdit(); self.netlify_token_input.setEchoMode(QLineEdit.EchoMode.Password); self.netlify_token_input.setPlaceholderText("Paste your Personal Access Token here")
        folder_layout = QHBoxLayout(); self.netlify_folder_input = QLineEdit()
        browse_button = QPushButton("Browse..."); folder_layout.addWidget(self.netlify_folder_input); folder_layout.addWidget(browse_button)
        layout.addRow("Netlify Access Token:", self.netlify_token_input); layout.addRow("Project Folder:", folder_layout)
        browse_button.clicked.connect(lambda: self.browse_project_folder(self.netlify_folder_input))
        return widget

    def create_vercel_ui(self):
        widget = QWidget(); layout = QFormLayout(widget); layout.setContentsMargins(0, 10, 0, 0)
        folder_layout = QHBoxLayout(); self.vercel_folder_input = QLineEdit()
        browse_button = QPushButton("Browse..."); folder_layout.addWidget(self.vercel_folder_input); folder_layout.addWidget(browse_button)
        layout.addRow("Project Folder:", folder_layout)
        browse_button.clicked.connect(lambda: self.browse_project_folder(self.vercel_folder_input))
        return widget

    def create_paas_deploy_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Provider selection
        provider_layout = QHBoxLayout()
        self.paas_provider_combo = QComboBox()
        self.paas_provider_combo.addItems(["Netlify", "Vercel"])
        provider_layout.addWidget(QLabel("PaaS Provider:"))
        provider_layout.addWidget(self.paas_provider_combo)
        provider_layout.addStretch()

        # Stacked widget for provider-specific UI
        self.paas_stacked_widget = QStackedWidget()
        self.paas_stacked_widget.addWidget(self.create_netlify_ui())
        self.paas_stacked_widget.addWidget(self.create_vercel_ui())

        layout.addLayout(provider_layout)
        layout.addWidget(self.paas_stacked_widget)

        self.paas_provider_combo.currentIndexChanged.connect(self.on_paas_provider_changed)
        return widget

    def browse_project_folder(self, target_line_edit):
        folder = QFileDialog.getExistingDirectory(self, "Select Project Folder")
        if folder: target_line_edit.setText(folder)

    def on_main_tab_changed(self, index):
        tab_text = self.tab_widget.tabText(index)
        if "Deploy" in tab_text:
            self.start_button.setText("Deploy")
            self.service_combo.setEnabled(False)
            self.port_spinner.setEnabled(False)
            self.auth_checkbox.setEnabled(False)
        else:
            self.start_button.setText("Start Tunnel")
            self.service_combo.setEnabled(True)
            self.port_spinner.setEnabled(True)
            self.auth_checkbox.setEnabled(True)

    def on_paas_provider_changed(self, index):
        self.paas_stacked_widget.setCurrentIndex(index)
        provider_name = self.paas_provider_combo.currentText()
        self.start_button.setText(f"Deploy to {provider_name}")

    def refresh_docker_containers(self):
        if not docker: self.log("Docker SDK not installed. Please run 'pip install docker'."); return
        self.log("Refreshing Docker container list..."); self.docker_refresh_button.setEnabled(False)
        self.data_worker_thread = QThread()
        # Assign worker to self to prevent it from being garbage collected before it's done.
        self.data_worker = DockerListContainersWorker()
        self.data_worker.moveToThread(self.data_worker_thread)
        self.data_worker.finished.connect(self.on_docker_containers_listed); self.data_worker.error_received.connect(self.log)
        self.data_worker_thread.started.connect(self.data_worker.run); self.data_worker_thread.start()

    def on_docker_containers_listed(self, containers):
        self.docker_container_combo.clear(); self.docker_volumes_tree.clear()
        if not containers: self.log("No running Docker containers found.")
        else:
            self.log(f"Found {len(containers)} running containers.")
            for c in containers:
                image_tag = 'unknown'
                try:
                    # A container's image might be deleted, so c.image could be None or raise an error.
                    if c.image and c.image.tags:
                        image_tag = c.image.tags[0]
                except Exception: pass # Gracefully handle missing image/tags
                self.docker_container_combo.addItem(f"{c.name} ({image_tag})", c.id)
        self.docker_refresh_button.setEnabled(True)

    def on_docker_container_selected(self, index):
        if index == -1: return
        container_id = self.docker_container_combo.itemData(index)
        client = docker.from_env(); container = client.containers.get(container_id)
        self.docker_volumes_tree.clear()
        for mount in container.attrs.get('Mounts', []):
            item = QTreeWidgetItem(self.docker_volumes_tree, [f"Mount: {mount['Destination']}"])
            item.setData(0, Qt.ItemDataRole.UserRole, mount['Destination'])

    def log(self, message):
        """Appends a message to the status output box."""
        self.status_output.append(str(message))

    def start_action(self):
        self.set_ui_enabled(False)
        self.status_output.clear()
        current_tab_text = self.tab_widget.tabText(self.tab_widget.currentIndex())
        if "Deploy" in current_tab_text:
            self.start_paas_deploy()
        else:
            self.start_tunnel_flow()

    def start_tunnel_flow(self):
        current_tab_text = self.tab_widget.tabText(self.tab_widget.currentIndex())
        if current_tab_text == "Local Share":
            path = self.local_path_input.text()
            if not path or not os.path.exists(path): self.log("Error: Please select a valid local path."); self.reset_ui_on_error(); return
            self.start_web_server(os.path.dirname(path) if os.path.isfile(path) else path)
        elif current_tab_text == "Remote Share (SSH)":
            self.start_remote_download()
        elif current_tab_text == "Container Share (CaaS)":
            self.start_docker_copy()

    def start_remote_download(self):
        host, user, remote_path = self.ssh_host_input.text(), self.ssh_user_input.text(), self.ssh_remote_path_input.text()
        if not all([host, user, remote_path]): self.log("Error: Host, Username, and Remote Path are required."); self.reset_ui_on_error(); return
        self.log(f"Connecting to {user}@{host}...")        
        self.data_worker_thread = QThread()
        # Assign worker to self to prevent it from being garbage collected before it's done.        
        self.data_worker = SftpDownloadWorker(host, self.ssh_port_spinner.value(), user, self.ssh_pass_input.text() if self.auth_pass_radio.isChecked() else None, self.ssh_key_path_input.text() if self.auth_key_radio.isChecked() else None, remote_path)
        self.data_worker.moveToThread(self.data_worker_thread)
        self.data_worker.finished.connect(self.on_data_fetch_complete); self.data_worker.error_received.connect(self.log_and_reset)
        self.data_worker_thread.started.connect(self.data_worker.run); self.data_worker_thread.start()

    def start_docker_copy(self):
        selected_items = self.docker_volumes_tree.selectedItems()
        if not selected_items: self.log("Error: Please select a volume to share."); self.reset_ui_on_error(); return
        container_id, volume_path = self.docker_container_combo.currentData(), selected_items[0].data(0, Qt.ItemDataRole.UserRole)
        self.log(f"Copying '{volume_path}' from container...")
        self.data_worker_thread = QThread()
        # Assign worker to self to prevent it from being garbage collected before it's done.
        self.data_worker = DockerCopyWorker(container_id, volume_path)
        self.data_worker.moveToThread(self.data_worker_thread)
        self.data_worker.finished.connect(self.on_data_fetch_complete); self.data_worker.error_received.connect(self.log_and_reset)
        self.data_worker_thread.started.connect(self.data_worker.run); self.data_worker_thread.start()

    def on_data_fetch_complete(self, temp_dir):        
        self.log(f"Data successfully copied to temporary location: {temp_dir}")
        self.temp_dir_path = temp_dir
        self.start_web_server(temp_dir)

    def start_web_server(self, directory_to_serve):
        self.log(f"Starting local web server for: {directory_to_serve}")
        username, password = (self.user_input.text(), self.pass_input.text()) if self.auth_checkbox.isChecked() else (None, None)
        self.web_server_thread = QThread()
        self.web_server_worker = WebServerWorker(directory_to_serve, self.port_spinner.value(), username, password)
        self.web_server_worker.moveToThread(self.web_server_thread)
        self.web_server_worker.server_started.connect(self.on_server_started); self.web_server_worker.error_received.connect(self.log_and_reset)        
        self.web_server_thread.started.connect(self.web_server_worker.run); self.web_server_thread.start()

    def on_server_started(self, host, port):
        self.log(f"Local web server started at http://{host}:{port}")
        service = self.service_combo.currentText()
        self.log(f"Starting {service} tunnel...")
        self.tunnel_thread = QThread()
        worker_class = self.tunnel_worker_map.get(service)
        if not worker_class: self.log_and_reset(f"Error: Unknown service '{service}'."); return
        self.tunnel_worker = worker_class(port)
        self.tunnel_worker.moveToThread(self.tunnel_thread)
        self.tunnel_worker.url_received.connect(self.on_url_received); self.tunnel_worker.error_received.connect(self.log_and_reset)
        self.tunnel_thread.started.connect(self.tunnel_worker.run); self.tunnel_thread.start()

    def start_paas_deploy(self):
        provider = self.paas_provider_combo.currentText()
        self.log(f"Starting deployment to {provider}...")
        self.paas_thread = QThread()
        if provider == "Netlify":
            token, folder = self.netlify_token_input.text(), self.netlify_folder_input.text()
            if not token or not folder: self.log("Error: Netlify token and folder required."); self.reset_ui_on_error(); return
            self.paas_worker = NetlifyDeployWorker(token, folder)
        elif provider == "Vercel":
            folder = self.vercel_folder_input.text()
            if not folder: self.log("Error: Vercel project folder required."); self.reset_ui_on_error(); return
            self.paas_worker = VercelDeployWorker(folder)
        else: self.log(f"Deployment for {provider} is not yet implemented."); self.reset_ui_on_error(); return
        self.paas_worker.moveToThread(self.paas_thread)
        self.paas_worker.finished.connect(self.on_paas_deploy_finished); self.paas_worker.error_received.connect(self.log_and_reset)
        self.paas_worker.log_message.connect(self.log)
        self.paas_thread.started.connect(self.paas_worker.run); self.paas_thread.start()

    def on_url_received(self, url):
        self.log("-----------------------------------------")
        self.log(f"SUCCESS! Your content is live at: {url}")
        self.log("-----------------------------------------")

    def on_paas_deploy_finished(self, url):
        self.log("-----------------------------------------")
        self.log(f"SUCCESS! Your site is live at: {url}")
        self.log("-----------------------------------------")
        self.reset_ui_on_error()

    def log_and_reset(self, error_message):
        self.log(f"ERROR: {error_message}")
        self.stop_all_services()

    def reset_ui_on_error(self):
        self.set_ui_enabled(True)

    def stop_all_services(self):
        self.log("Stopping all services...")

        # Stop workers first to signal them to finish their tasks.
        if self.tunnel_worker: self.tunnel_worker.stop()        
        if self.web_server_worker: self.web_server_worker.stop()
        # Data and PaaS workers are short-lived and don't have stop methods,
        # but we must wait for their threads to finish cleanly.

        # Gracefully quit and wait for all threads to terminate. This prevents the
        # "QThread: Destroyed while thread is still running" error.
        threads_to_wait = [
            (self.tunnel_thread, "Tunnel"), (self.web_server_thread, "Web Server"),
            (self.data_worker_thread, "Data Worker"), (self.paas_thread, "PaaS Worker")
        ]
        for thread, name in threads_to_wait:
            if thread and thread.isRunning():
                thread.quit()
                if not thread.wait(3000): # Wait up to 3 seconds
                    self.log(f"Warning: {name} thread did not terminate gracefully.")
                    thread.terminate() # Forcefully stop if it doesn't respond

        if self.temp_dir_path:
            shutil.rmtree(self.temp_dir_path, ignore_errors=True)
            self.log(f"Cleaned up temporary directory: {self.temp_dir_path}")
            self.temp_dir_path = None

        self.set_ui_enabled(True)
        self.log("All services stopped.")        

    def set_ui_enabled(self, enabled):
        self.start_button.setEnabled(enabled)
        self.stop_button.setEnabled(not enabled)
        self.tab_widget.setEnabled(enabled)
        self.service_combo.setEnabled(enabled)
        self.port_spinner.setEnabled(enabled)
        self.auth_checkbox.setEnabled(enabled)        
        if enabled: self.on_main_tab_changed(self.tab_widget.currentIndex()) # Restore correct button text/state
        else: self.user_input.setEnabled(False); self.pass_input.setEnabled(False)

    def closeEvent(self, event):
        self.stop_all_services()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
