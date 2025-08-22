import subprocess
import time
import os
import signal
import tempfile
import shutil
import pytest

SERVER_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '../server/simple_server.py'))
CLIENT_BIN = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '../client/build/tcp_client'))


@pytest.fixture(scope="module")
def server():
    # Start the server as a subprocess
    proc = subprocess.Popen(
        ['python3', SERVER_PATH], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1)  # Give server time to start
    yield proc
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture
def temp_dir(tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(cwd)


@pytest.fixture
def server_info_file(temp_dir):
    # Write server.info file for the client
    with open('server.info', 'w') as f:
        f.write('127.0.0.1:12345\n')
    return 'server.info'


def run_client(commands, cwd):
    # Run the client binary, send commands via stdin, capture stdout
    proc = subprocess.Popen([CLIENT_BIN], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=cwd)
    out, _ = proc.communicate('\n'.join(commands) + '\n', timeout=10)
    return out


def test_register_and_client_list(server, server_info_file, temp_dir):
    # Register first client in its own dir, then get list
    client1_dir = temp_dir / "client1"
    client1_dir.mkdir()
    shutil.copy(server_info_file, client1_dir / "server.info")
    out1 = run_client(['110', 'alice', '120', '0'], client1_dir)
    assert 'Registration successful' in out1
    assert 'Client list received and saved.' in out1

    # Register second client in its own dir, then get list
    client2_dir = temp_dir / "client2"
    client2_dir.mkdir()
    shutil.copy(server_info_file, client2_dir / "server.info")
    out2 = run_client(['110', 'bob', '120', '0'], client2_dir)
    assert 'Registration successful' in out2
    assert 'Client list received and saved.' in out2
    assert "alice" in out2
