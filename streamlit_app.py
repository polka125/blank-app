print("hi there")

import sys

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




import os
import stat
import pathlib
from typing import Set, List, Dict
import logging
from datetime import datetime
import platform
import sys
from collections import defaultdict
import traceback

def scan_paths(start_path: str = '/', 
              max_depth: int = None,
              exclude_paths: Set[str] = None,
              follow_links: bool = False) -> Dict[str, dict]:
    """
    Comprehensive path scanner with error handling and detailed stats
    
    Args:
        start_path: Root path to start scanning from
        max_depth: Maximum directory depth to scan
        exclude_paths: Set of paths to exclude
        follow_links: Whether to follow symbolic links
    
    Returns:
        Dictionary with path information and statistics
    """
    if exclude_paths is None:
        exclude_paths = {'/proc', '/sys', '/dev', '/run', '/var/run', '/var/lock'}
    
    result = {
        'paths': defaultdict(dict),
        'stats': {
            'total_files': 0,
            'total_dirs': 0,
            'total_links': 0,
            'total_size': 0,
            'errors': [],
            'start_time': datetime.now(),
            'end_time': None,
            'system_info': {
                'platform': platform.platform(),
                'python_version': sys.version,
                'machine': platform.machine(),
                'node': platform.node()
            }
        }
    }

    def get_path_info(path: str) -> dict:
        """Get detailed information about a path"""
        try:
            st = os.stat(path, follow_symlinks=follow_links)
            info = {
                'size': st.st_size,
                'modified': datetime.fromtimestamp(st.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(st.st_atime).isoformat(),
                'created': datetime.fromtimestamp(st.st_ctime).isoformat(),
                'mode': stat.filemode(st.st_mode),
                'uid': st.st_uid,
                'gid': st.st_gid,
                'is_file': stat.S_ISREG(st.st_mode),
                'is_dir': stat.S_ISDIR(st.st_mode),
                'is_link': stat.S_ISLNK(st.st_mode),
                'is_mount': os.path.ismount(path)
            }
            
            if os.path.islink(path):
                info['link_target'] = os.readlink(path)
            
            return info
        except Exception as e:
            error = f"Error getting info for {path}: {str(e)}"
            result['stats']['errors'].append(error)
            return {'error': error}

    def scan_directory(current_path: str, current_depth: int = 0):
        """Recursively scan directory with depth tracking"""
        if max_depth is not None and current_depth > max_depth:
            return

        if current_path in exclude_paths:
            return

        try:
            # Get directory contents
            with os.scandir(current_path) as entries:
                for entry in entries:
                    try:
                        path = entry.path
                        
                        # Skip excluded paths
                        if any(excluded in path for excluded in exclude_paths):
                            continue

                        # Get path information
                        info = get_path_info(path)
                        result['paths'][path] = info

                        # Update statistics
                        if info.get('is_file'):
                            result['stats']['total_files'] += 1
                            result['stats']['total_size'] += info.get('size', 0)
                        if info.get('is_dir'):
                            result['stats']['total_dirs'] += 1
                        if info.get('is_link'):
                            result['stats']['total_links'] += 1

                        # Recurse into directories
                        if info.get('is_dir'):
                            if follow_links or not info.get('is_link'):
                                scan_directory(path, current_depth + 1)

                    except Exception as e:
                        error = f"Error processing {path}: {str(e)}\n{traceback.format_exc()}"
                        result['stats']['errors'].append(error)

        except Exception as e:
            error = f"Error scanning directory {current_path}: {str(e)}\n{traceback.format_exc()}"
            result['stats']['errors'].append(error)

    try:
        # Start scanning from root path
        scan_directory(start_path)
        
    except Exception as e:
        error = f"Fatal error during scan: {str(e)}\n{traceback.format_exc()}"
        result['stats']['errors'].append(error)
    
    finally:
        result['stats']['end_time'] = datetime.now()
        result['stats']['duration'] = (
            result['stats']['end_time'] - 
            result['stats']['start_time']
        ).total_seconds()
        
        # Add permission denied count
        result['stats']['permission_denied'] = sum(
            1 for error in result['stats']['errors'] 
            if 'Permission denied' in error
        )
        
        # Add summary
        result['stats']['summary'] = (
            f"Scanned {result['stats']['total_dirs']} directories, "
            f"{result['stats']['total_files']} files, "
            f"{result['stats']['total_links']} links. "
            f"Total size: {result['stats']['total_size']} bytes. "
            f"Errors: {len(result['stats']['errors'])} "
            f"(Permission denied: {result['stats']['permission_denied']})"
        )

    return result



def format_scan_results(result: dict, show_errors: bool = True, indent: str = "  ") -> str:
    """
    Format scan results into a readable string
    
    Args:
        result: The dictionary returned by scan_paths()
        show_errors: Whether to include error messages
        indent: Indentation string for formatting
    """
    output = []
    stats = result['stats']
    
    # System Information
    output.append("System Information:")
    for key, value in stats['system_info'].items():
        output.append(f"{indent}{key}: {value}")
    
    # Scan Statistics
    output.append("\nScan Statistics:")
    output.append(f"{indent}Start Time: {stats['start_time']}")
    output.append(f"{indent}End Time: {stats['end_time']}")
    output.append(f"{indent}Duration: {stats['duration']:.2f} seconds")
    output.append(f"{indent}Total Directories: {stats['total_dirs']:,}")
    output.append(f"{indent}Total Files: {stats['total_files']:,}")
    output.append(f"{indent}Total Links: {stats['total_links']:,}")
    output.append(f"{indent}Total Size: {stats['total_size']:,} bytes ({stats['total_size'] / (1024*1024*1024):.2f} GB)")
    
    # Path Information
    output.append("\nLarge Files (>100MB):")
    large_files = {
        path: info for path, info in result['paths'].items() 
        if info.get('size', 0) > 100*1024*1024  # 100MB
    }
    if large_files:
        for path, info in sorted(large_files.items(), key=lambda x: x[1].get('size', 0), reverse=True):
            size_mb = info.get('size', 0) / (1024*1024)
            output.append(f"{indent}{path}")
            output.append(f"{indent}{indent}Size: {size_mb:.2f} MB")
            output.append(f"{indent}{indent}Modified: {info.get('modified', 'N/A')}")
            output.append(f"{indent}{indent}Mode: {info.get('mode', 'N/A')}")
    else:
        output.append(f"{indent}None found")
    
    # Mount Points
    output.append("\nMount Points:")
    mount_points = {
        path: info for path, info in result['paths'].items() 
        if info.get('is_mount')
    }
    if mount_points:
        for path in sorted(mount_points.keys()):
            output.append(f"{indent}{path}")
    else:
        output.append(f"{indent}None found")
    
    # Errors
    if show_errors and stats['errors']:
        output.append("\nErrors:")
        output.append(f"{indent}Total Errors: {len(stats['errors'])}")
        output.append(f"{indent}Permission Denied: {stats.get('permission_denied', 0)}")
        output.append("\nError Details:")
        for error in stats['errors'][:10]:  # Show first 10 errors
            output.append(f"{indent}{error}")
        if len(stats['errors']) > 10:
            output.append(f"{indent}... and {len(stats['errors']) - 10} more errors")
    
    return "\n".join(output)


scan_result = scan_paths(os.path.expanduser('~/../'))
formatted_output = format_scan_results(scan_result)
st.write(formatted_output)