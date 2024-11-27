print("hi there")

import sys
sys.exit(0)

import streamlit as st

st.title("🎈 My new app")
st.write(
    "Let's start building! For help and inspiration, head over to [docs.streamlit.io](https://docs.streamlit.io/)."
)

st.write("new here!")

import os
st.write(str(os.path.exists('/.dockerenv')))



try:
    import os
    import sys
    import platform
    import pkg_resources
    import getpass
    from datetime import datetime

    def is_running_in_docker():
        """Check if the code is running inside a Docker container"""
        path_list = [
            '/.dockerenv',      # Check for .dockerenv file
            '/proc/1/cgroup'    # Check for Docker cgroup
        ]
        
        # Check for .dockerenv file
        docker_env = os.path.exists('/.dockerenv')
        
        # Check cgroup
        docker_cgroup = False
        try:
            with open('/proc/1/cgroup', 'r') as f:
                docker_cgroup = any('docker' in line for line in f)
        except:
            pass
        
        return docker_env or docker_cgroup

    st.write(str(is_running_in_docker()))

    def gather_docker_info():
        """Gather all available Docker-related information"""
        if not is_running_in_docker():
            return "Not running in Docker container"
        
        docker_info = []
        
        # Get container ID
        try:
            with open('/proc/1/cpuset') as f:
                container_id = f.read().strip().split('/')[-1]
            docker_info.append(f"Container ID: {container_id}")
        except:
            docker_info.append("Container ID: Unable to determine")

        # Get container hostname
        try:
            hostname = platform.node()
            docker_info.append(f"Container Hostname: {hostname}")
        except:
            docker_info.append("Container Hostname: Unable to determine")

        # Get cgroup information
        try:
            with open('/proc/1/cgroup', 'r') as f:
                cgroup_info = f.read().strip()
            docker_info.append("\nCgroup Information:\n" + cgroup_info)
        except:
            docker_info.append("Cgroup Information: Unable to read")

        # Get container limits
        limits_files = {
            'CPU Shares': '/sys/fs/cgroup/cpu/cpu.shares',
            'Memory Limit': '/sys/fs/cgroup/memory/memory.limit_in_bytes',
            'Memory Usage': '/sys/fs/cgroup/memory/memory.usage_in_bytes'
        }
        
        docker_info.append("\nContainer Limits:")
        for limit_name, limit_file in limits_files.items():
            try:
                with open(limit_file, 'r') as f:
                    value = f.read().strip()
                    docker_info.append(f"{limit_name}: {value}")
            except:
                docker_info.append(f"{limit_name}: Unable to read")

        # Get mounted volumes
        try:
            with open('/proc/mounts', 'r') as f:
                mounts = f.read().strip()
            docker_info.append("\nMounted Volumes:\n" + mounts)
        except:
            docker_info.append("Mounted Volumes: Unable to read")

        # Get environment variables that might be Docker-related
        docker_env_vars = {k: v for k, v in os.environ.items() 
                        if any(x in k.lower() for x in ['docker', 'container', 'kubernetes', 'k8s'])}
        if docker_env_vars:
            docker_info.append("\nDocker-related Environment Variables:")
            for k, v in docker_env_vars.items():
                docker_info.append(f"{k}={v}")

        return "\n".join(docker_info)

    st.write(gather_docker_info())

    def get_system_info():
        # Basic info
        current_dir = os.getcwd()
        system_path = os.environ.get('PATH')
        current_user = getpass.getuser()
        
        # System info
        system_info = platform.uname()
        python_version = sys.version
        
        # Installed packages
        installed_packages = [f"{pkg.key} ({pkg.version})" 
                            for pkg in pkg_resources.working_set]
        
        # Environment variables
        env_vars = dict(os.environ)
        
        # Python paths
        python_path = sys.path
        
        # Docker information
        docker_status = "Running in Docker container" if is_running_in_docker() else "Not running in Docker container"
        docker_details = gather_docker_info() if is_running_in_docker() else ""
        
        info = f"""
    System Information:
    ==================
    Time: {datetime.now()}
    Current Directory: {current_dir}
    Current User: {current_user}

    Docker Status:
    -------------
    {docker_status}

    {docker_details}

    System Details:
    --------------
    OS: {system_info.system} {system_info.release}
    Machine: {system_info.machine}
    Processor: {system_info.processor}
    Python Version: {python_version.split()[0]}
    Platform: {platform.platform()}

    Python Configuration:
    -------------------
    Python Path:
    {chr(10).join(python_path)}

    Installed Python Packages:
    ------------------------
    {chr(10).join(sorted(installed_packages))}

    Environment Variables:
    --------------------
    {chr(10).join(f'{k}={v}' for k, v in sorted(env_vars.items()))}

    System PATH:
    -----------
    {system_path}
    """
        return info



    st.write(get_system_info())
except Exception as e:
    st.write(str(e))





import os
import sys
import platform
import pkg_resources
import getpass
from datetime import datetime
import subprocess


import shutil

def get_running_processes():
    """Get information about running processes"""
    if platform.system() == 'Windows':
        tasklist_path = shutil.which('tasklist')
        if not tasklist_path:
            return "Error: 'tasklist' command not found on Windows system"
        
        try:
            output = subprocess.check_output(['tasklist'], text=True)
            return output
        except subprocess.CalledProcessError as e:
            return f"Error running tasklist: {str(e)}"
        except Exception as e:
            return f"Unexpected error getting Windows process list: {str(e)}"
    else:
        # Check for ps command
        ps_path = shutil.which('ps')
        if not ps_path:
            # Try alternative ways to get process information
            try:
                # Using /proc directory (Linux)
                pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
                processes = []
                for pid in pids:
                    try:
                        with open(f'/proc/{pid}/status', 'r') as f:
                            status = f.read()
                        with open(f'/proc/{pid}/cmdline', 'r') as f:
                            cmdline = f.read()
                        processes.append(f"PID: {pid}\n{status}\nCommand: {cmdline}\n")
                    except:
                        continue
                return "\n".join(processes) if processes else "No process information available"
            except:
                return "Error: 'ps' command not found and /proc filesystem not accessible"
        
        try:
            output = subprocess.check_output(['ps', 'aux'], text=True)
            return output
        except subprocess.CalledProcessError as e:
            try:
                output = subprocess.check_output(['ps', '-ef'], text=True)
                return output
            except subprocess.CalledProcessError as e:
                return f"Error running ps command: {str(e)}"
            except Exception as e:
                return f"Unexpected error running ps -ef: {str(e)}"
        except Exception as e:
            return f"Unexpected error running ps aux: {str(e)}"


st.write(get_running_processes())