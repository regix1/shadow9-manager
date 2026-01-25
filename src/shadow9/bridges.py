"""
Tor Bridge and Pluggable Transport Support for Shadow9.

Provides stealth Tor connectivity using:
- obfs4 bridges (most effective against DPI)
- snowflake bridges (uses WebRTC)
- webtunnel bridges (looks like HTTPS)

This hides the fact that you're using Tor from network observers.

Bridge configurations are in bridge_list.py
"""

import asyncio
import subprocess
import shutil
import tempfile
import platform
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, field

import structlog

# Import bridge types and configurations from separate file
from .bridge_list import (
    BridgeType,
    Bridge,
    BUILTIN_OBFS4_BRIDGES,
    SNOWFLAKE_BRIDGES,
)

logger = structlog.get_logger(__name__)

# Module-level cache for bridge speedtest results
# This cache persists for the lifetime of the process, so subsequent users
# don't need to re-run speedtests. Cleared on service restart.
_bridge_speedtest_cache: dict[str, list[tuple["Bridge", float | None]]] = {}


@dataclass
class BridgeConfig:
    """Configuration for Tor bridges."""
    enabled: bool = False
    bridge_type: BridgeType = BridgeType.OBFS4
    bridges: List[Bridge] = field(default_factory=list)

    # Paths to pluggable transport binaries
    obfs4proxy_path: Optional[str] = None
    snowflake_path: Optional[str] = None
    webtunnel_path: Optional[str] = None

    # Use built-in bridges (requires no configuration)
    use_builtin_bridges: bool = True


class PluggableTransportManager:
    """
    Manages pluggable transport binaries and Tor bridge configuration.
    """

    def __init__(self, config: BridgeConfig):
        self.config = config
        self._obfs4proxy_proc: Optional[subprocess.Popen] = None
        self._snowflake_proc: Optional[subprocess.Popen] = None

    def detect_transports(self) -> dict[BridgeType, Optional[str]]:
        """
        Detect available pluggable transport binaries.

        Returns dict mapping transport type to binary path.
        """
        transports = {}

        # Look for obfs4proxy
        obfs4_names = ["obfs4proxy", "obfs4proxy.exe", "lyrebird", "lyrebird.exe"]
        for name in obfs4_names:
            path = shutil.which(name)
            if path:
                transports[BridgeType.OBFS4] = path
                break

        if self.config.obfs4proxy_path and Path(self.config.obfs4proxy_path).exists():
            transports[BridgeType.OBFS4] = self.config.obfs4proxy_path

        # Look for snowflake-client
        snowflake_names = ["snowflake-client", "snowflake-client.exe"]
        for name in snowflake_names:
            path = shutil.which(name)
            if path:
                transports[BridgeType.SNOWFLAKE] = path
                break

        if self.config.snowflake_path and Path(self.config.snowflake_path).exists():
            transports[BridgeType.SNOWFLAKE] = self.config.snowflake_path

        return transports

    def generate_torrc(
        self, 
        data_dir: Path, 
        socks_port: int = 9050, 
        control_port: int = 0,
        specific_bridge: Optional[Bridge] = None
    ) -> str:
        """
        Generate torrc configuration for bridges.

        Args:
            data_dir: Tor data directory
            socks_port: SOCKS port for this Tor instance
            control_port: Control port for this Tor instance (0 = auto-assign)
            specific_bridge: If provided, use only this specific bridge (for fallback testing)

        Returns:
            torrc content string
        """
        lines = [
            f"DataDirectory {data_dir}",
            f"SocksPort {socks_port}",
            "UseBridges 1",
        ]
        
        # Performance and timeout tuning for bridges (especially snowflake)
        # These settings help with slow connections and large transfers
        # Requires Tor 0.4.8+ (installed from official Tor Project repo)
        lines.extend([
            # Conflux: Split traffic across multiple circuits for ~30% speed boost
            # This uses two circuits to the same exit, optimizing for latency
            "ConfluxEnabled 1",
            "ConfluxClientUX latency",
            # Disable adaptive timeout learning, use fixed values
            "LearnCircuitBuildTimeout 0",
            # Higher timeout for bridges (snowflake is slow) - default is 60
            "CircuitBuildTimeout 120",
            # SOCKS timeout for client connections (default 120, increase for large pages)
            "SocksTimeout 300",
            # Keep circuits alive longer for large transfers (default 600)
            "MaxCircuitDirtiness 1800",
            # Don't close idle circuits quickly (default 3600)
            "CircuitIdleTimeout 3600",
            # Keep connections alive
            "KeepalivePeriod 60",
            # Don't retry too aggressively during transfers
            "NewCircuitPeriod 30",
            # Connection padding helps with stability
            "ConnectionPadding 1",
            # Reduce circuit preemption during active transfers
            "MaxClientCircuitsPending 64",
            # Hidden service (.onion) specific settings - requires Tor 0.4.5+
            # Don't give up on slow hidden service client circuits too quickly
            "CloseHSClientCircuitsImmediatelyOnTimeout 0",
            # Don't timeout hidden service rendezvous circuits too quickly  
            "CloseHSServiceRendCircuitsImmediatelyOnTimeout 0",
        ])

        # Add control port for bootstrap monitoring
        if control_port > 0:
            lines.append(f"ControlPort {control_port}")
        else:
            # Use auto port assignment with a socket file
            control_socket = data_dir / "control.sock"
            lines.append(f"ControlSocket {control_socket}")

        # Get bridges to use
        if specific_bridge:
            # Use only the specific bridge for fallback testing
            bridges = [specific_bridge]
        elif self.config.use_builtin_bridges and not self.config.bridges:
            if self.config.bridge_type == BridgeType.OBFS4:
                bridges = BUILTIN_OBFS4_BRIDGES
            elif self.config.bridge_type == BridgeType.SNOWFLAKE:
                # For snowflake, just use the first bridge - fallback is handled at higher level
                bridges = [SNOWFLAKE_BRIDGES[0]] if SNOWFLAKE_BRIDGES else []
            else:
                bridges = []
        else:
            bridges = self.config.bridges

        # Add bridge lines
        for bridge in bridges:
            bridge_line = bridge.to_bridge_line()
            if bridge_line:
                lines.append(bridge_line)

        # Add transport plugin configuration
        transports = self.detect_transports()

        if BridgeType.OBFS4 in transports and self.config.bridge_type == BridgeType.OBFS4:
            lines.append(f"ClientTransportPlugin obfs4 exec {transports[BridgeType.OBFS4]}")

        if BridgeType.SNOWFLAKE in transports and self.config.bridge_type == BridgeType.SNOWFLAKE:
            lines.append(f"ClientTransportPlugin snowflake exec {transports[BridgeType.SNOWFLAKE]}")

        return "\n".join(lines)
    
    def get_fallback_bridges(self) -> List[Bridge]:
        """Get list of bridges to try for fallback."""
        if self.config.bridge_type == BridgeType.SNOWFLAKE:
            return SNOWFLAKE_BRIDGES
        elif self.config.bridge_type == BridgeType.OBFS4:
            return BUILTIN_OBFS4_BRIDGES
        return []

    def get_install_instructions(self) -> str:
        """Get installation instructions for pluggable transports."""
        system = platform.system().lower()

        if system == "windows":
            return """
Pluggable Transport Installation (Windows):
1. Download Tor Browser from https://www.torproject.org/
2. The obfs4proxy.exe is included in: Tor Browser\\Browser\\TorBrowser\\Tor\\PluggableTransports\\
3. Add that path to your system PATH, or specify it in config

Alternative: Download standalone obfs4proxy from:
https://github.com/Yawning/obfs4/releases
"""
        elif system == "darwin":
            return """
Pluggable Transport Installation (macOS):
1. Using Homebrew: brew install obfs4proxy
2. Or download from Tor Browser bundle

For Snowflake:
brew install snowflake
"""
        else:  # Linux
            return """
Pluggable Transport Installation (Linux):
1. Ubuntu/Debian: sudo apt install obfs4proxy
2. Fedora: sudo dnf install obfs4
3. Arch: sudo pacman -S obfs4proxy

For Snowflake:
sudo apt install snowflake-client
"""

    async def check_transport_available(self, bridge_type: BridgeType) -> bool:
        """Check if the required pluggable transport is available."""
        transports = self.detect_transports()
        return bridge_type in transports


class TorBridgeConnector:
    """
    Connects to Tor network using bridges for stealth.

    This makes your Tor connection undetectable by:
    - Using obfs4 to obfuscate traffic patterns

    - Using snowflake to use WebRTC peer connections
    """

    def __init__(self, bridge_config: BridgeConfig, socks_port: int = 9050):
        self.config = bridge_config
        self.socks_port = socks_port
        self.pt_manager = PluggableTransportManager(bridge_config)
        self._tor_process: Optional[subprocess.Popen] = None
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self._data_dir: Optional[Path] = None
        self._log_file: Optional[Path] = None
        self._current_bridge: Optional[Bridge] = None  # Track which bridge is working

    async def start_tor_with_bridges(self) -> tuple[str, int]:
        """
        Start a Tor process configured with bridges.
        
        For snowflake bridges, this will:
        1. Run a quick speed test on all bridges (measure time to reach 15%)
        2. Sort bridges by speed (fastest first)
        3. Try to fully connect using the fastest bridges first

        Returns:
            Tuple of (socks_host, socks_port)
        """
        # Check if transport is available
        if not await self.pt_manager.check_transport_available(self.config.bridge_type):
            logger.warning(
                f"Pluggable transport {self.config.bridge_type.value} not found",
            )
            print(self.pt_manager.get_install_instructions())
            raise RuntimeError(f"Pluggable transport {self.config.bridge_type.value} not installed")

        # Get list of bridges to try
        fallback_bridges = self.pt_manager.get_fallback_bridges()
        
        if not fallback_bridges:
            # No fallback list, use default behavior
            return await self._try_single_bridge(None)
        
        # Phase 1: Speed test all bridges (with caching)
        cache_key = self.config.bridge_type.value
        
        if cache_key in _bridge_speedtest_cache:
            # Use cached speedtest results
            sorted_bridges = _bridge_speedtest_cache[cache_key]
            print(f"\n  Using cached speedtest results for {len(sorted_bridges)} bridges...")
            print("\n  Cached speed test results:")
            for bridge, speed in sorted_bridges:
                bridge_name = bridge.params.get("front", bridge.params.get("url", "unknown"))
                if speed is not None:
                    print(f"    {bridge_name}: {speed:.1f}s to 15%")
                else:
                    print(f"    {bridge_name}: failed/timeout")
        else:
            # Run speedtests
            print(f"\n  Testing {len(fallback_bridges)} bridges for speed...")
            bridge_speeds = await self._test_bridge_speeds(fallback_bridges)
            
            # Sort by speed (fastest first), failed bridges at the end
            sorted_bridges = sorted(
                bridge_speeds,
                key=lambda x: x[1] if x[1] is not None else float('inf')
            )
            
            # Show speed test results
            print("\n  Speed test results:")
            for bridge, speed in sorted_bridges:
                bridge_name = bridge.params.get("front", bridge.params.get("url", "unknown"))
                if speed is not None:
                    print(f"    {bridge_name}: {speed:.1f}s to 15%")
                else:
                    print(f"    {bridge_name}: failed/timeout")
            
            # Only cache if at least one bridge succeeded
            working_count = sum(1 for _, s in sorted_bridges if s is not None)
            if working_count > 0:
                _bridge_speedtest_cache[cache_key] = sorted_bridges
                logger.info(f"Cached speedtest results for bridge type: {cache_key}")
            else:
                logger.warning(f"Not caching speedtest results - all {len(sorted_bridges)} bridges failed")
        
        # Filter to only working bridges
        working_bridges = [(b, s) for b, s in sorted_bridges if s is not None]
        
        if not working_bridges:
            raise RuntimeError("All bridges failed speed test - none could reach 15% bootstrap")
        
        print("\n  Connecting using fastest bridge...")
        
        # Phase 2: Try to fully connect using sorted bridges (fastest first)
        last_error = None
        for i, (bridge, speed) in enumerate(working_bridges):
            bridge_name = bridge.params.get("front", bridge.params.get("url", "unknown"))
            logger.info(
                f"Connecting with bridge {i+1}/{len(working_bridges)}: {bridge_name} ({speed:.1f}s)",
                bridge_type=self.config.bridge_type.value
            )
            print(f"  Trying {bridge_name} (ranked #{i+1} by speed)...")
            
            try:
                result = await self._try_single_bridge(bridge, timeout=180)  # 3 min for full connect
                self._current_bridge = bridge
                logger.info(f"Successfully connected using bridge: {bridge_name}")
                print(f"  ✓ Connected using: {bridge_name}")
                return result
            except RuntimeError as e:
                last_error = e
                logger.warning(f"Bridge {bridge_name} failed: {e}")
                print(f"  ✗ Bridge failed: {bridge_name}")
                # Cleanup before trying next bridge
                await self._cleanup_tor()
                continue
        
        # All bridges failed
        raise RuntimeError(f"All {len(working_bridges)} bridges failed to connect. Last error: {last_error}")

    async def _test_bridge_speeds(self, bridges: List[Bridge]) -> List[tuple[Bridge, Optional[float]]]:
        """
        Test multiple bridges in parallel and measure time to reach 15% bootstrap.
        
        Returns:
            List of (bridge, time_to_15_percent) tuples. time is None if failed.
        """
        
        results = []
        test_timeout = 30  # 30 seconds max per bridge for speed test
        target_progress = 15  # Target bootstrap percentage for speed test
        first_test = True
        
        for bridge in bridges:
            bridge_name = bridge.params.get("front", bridge.params.get("url", "unknown"))
            print(f"    Testing {bridge_name}...", end=" ", flush=True)
            
            speed, error = await self._quick_bridge_test(bridge, test_timeout, target_progress, show_config=first_test)
            first_test = False
            
            if speed is not None:
                print(f"{speed:.1f}s")
            elif error:
                print(f"FAILED: {error}")
            else:
                print("timeout/failed")
            
            results.append((bridge, speed))
        
        return results

    async def _quick_bridge_test(self, bridge: Bridge, timeout: int, target_progress: int, show_config: bool = False) -> tuple[Optional[float], Optional[str]]:
        """
        Quick test a bridge - measure time to reach target bootstrap percentage.
        
        Returns:
            Tuple of (time_in_seconds, error_message). time is None if failed, error is None if succeeded.
        """
        import re
        import time as time_module
        
        temp_dir = None
        tor_process = None
        bridge_name = bridge.params.get("front", bridge.params.get("url", "unknown"))
        
        try:
            # Create temp directory
            temp_dir = tempfile.TemporaryDirectory(prefix="shadow9_test_")
            data_dir = Path(temp_dir.name)
            
            # Use a different port for testing to avoid conflicts
            test_port = self.socks_port + 100 + hash(bridge.address) % 100
            
            # Generate torrc
            torrc_content = self.pt_manager.generate_torrc(
                data_dir, 
                test_port,
                specific_bridge=bridge
            )
            
            # Add log file - use stdout for immediate feedback
            log_file = data_dir / "tor.log"
            torrc_content += f"\nLog notice file {log_file}"
            torrc_content += f"\nLog notice stdout"
            
            torrc_path = data_dir / "torrc"
            torrc_path.write_text(torrc_content)
            
            # Show config for first test to help debug
            if show_config:
                print(f"\n    [DEBUG] First test torrc:\n")
                for line in torrc_content.splitlines():
                    print(f"      {line}")
                print(f"\n    Testing {bridge_name}...", end=" ", flush=True)
            
            # Find tor binary
            tor_path = shutil.which("tor")
            if not tor_path:
                return None, "tor binary not found"
            
            # Start Tor process - capture both stdout and stderr
            tor_process = subprocess.Popen(
                [tor_path, "-f", str(torrc_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
            )
            
            start_time = time_module.time()
            output_lines = []
            
            while True:
                elapsed = time_module.time() - start_time
                if elapsed > timeout:
                    return None, None  # Timeout (no error message needed)
                
                # Non-blocking read from stdout
                if tor_process.stdout:
                    import select
                    try:
                        # Try to read available output (works on Unix)
                        while True:
                            ready, _, _ = select.select([tor_process.stdout], [], [], 0)
                            if not ready:
                                break
                            line = tor_process.stdout.readline()
                            if line:
                                output_lines.append(line.decode('utf-8', errors='ignore').strip())
                            else:
                                break
                    except Exception:
                        # On Windows or error, try different approach
                        pass
                
                poll_result = tor_process.poll()
                if poll_result is not None:
                    # Process exited - get remaining output
                    try:
                        remaining, _ = tor_process.communicate(timeout=1)
                        if remaining:
                            output_lines.extend(remaining.decode('utf-8', errors='ignore').strip().splitlines())
                    except Exception:
                        pass
                    
                    # Find error message in output
                    error_detail = ""
                    for line in reversed(output_lines):
                        line_lower = line.lower()
                        if 'error' in line_lower or 'failed' in line_lower or '[err]' in line_lower or '[warn]' in line_lower:
                            # Clean up the line
                            if ']' in line:
                                error_detail = line.split(']')[-1].strip()[:100]
                            else:
                                error_detail = line[:100]
                            break
                    
                    # If no error found but process failed, show last line
                    if not error_detail and output_lines:
                        error_detail = output_lines[-1][:100]
                    
                    # If still nothing, check log file
                    if not error_detail:
                        try:
                            if log_file.exists():
                                log_content = log_file.read_text()
                                if log_content.strip():
                                    last_line = log_content.strip().splitlines()[-1]
                                    error_detail = last_line[:100]
                        except Exception:
                            pass
                    
                    return None, f"Tor exit {poll_result}: {error_detail}" if error_detail else f"Tor exit {poll_result}"
                
                # Check for bootstrap progress in collected output
                for line in output_lines:
                    if 'Bootstrapped' in line:
                        match = re.search(r'Bootstrapped (\d+)%', line)
                        if match:
                            progress = int(match.group(1))
                            if progress >= target_progress:
                                return time_module.time() - start_time, None
                
                # Also check log file for bootstrap progress
                try:
                    if log_file.exists():
                        log_content = log_file.read_text()
                        for line in log_content.splitlines():
                            if 'Bootstrapped' in line:
                                match = re.search(r'Bootstrapped (\d+)%', line)
                                if match:
                                    progress = int(match.group(1))
                                    if progress >= target_progress:
                                        return time_module.time() - start_time, None
                except Exception:
                    pass
                
                await asyncio.sleep(0.5)
                
        except Exception as e:
            return None, f"{type(e).__name__}: {str(e)[:80]}"
        finally:
            # Cleanup
            if tor_process:
                tor_process.terminate()
                try:
                    tor_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    tor_process.kill()
            if temp_dir:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass

    async def _try_single_bridge(self, bridge: Optional[Bridge], timeout: int = 180) -> tuple[str, int]:
        """
        Try to start Tor with a specific bridge.
        
        Args:
            bridge: Specific bridge to use, or None for default behavior
            timeout: Bootstrap timeout in seconds
            
        Returns:
            Tuple of (socks_host, socks_port)
        """
        # Create temp directory for Tor data
        self._temp_dir = tempfile.TemporaryDirectory(prefix="shadow9_tor_")
        self._data_dir = Path(self._temp_dir.name)

        # Generate torrc with specified port and specific bridge
        torrc_content = self.pt_manager.generate_torrc(
            self._data_dir, 
            self.socks_port,
            specific_bridge=bridge
        )
        
        # Add log file to torrc for bootstrap monitoring
        self._log_file = self._data_dir / "tor.log"
        torrc_content += f"\nLog notice file {self._log_file}"
        
        torrc_path = self._data_dir / "torrc"
        torrc_path.write_text(torrc_content)

        bridge_name = "default"
        if bridge:
            bridge_name = bridge.params.get("front", bridge.params.get("url", "unknown"))

        logger.info(
            "Starting Tor with bridges",
            bridge_type=self.config.bridge_type.value,
            bridge=bridge_name,
            socks_port=self.socks_port,
            torrc=str(torrc_path)
        )

        # Find tor binary
        tor_path = shutil.which("tor")
        if not tor_path:
            raise RuntimeError("Tor not found. Please install Tor.")

        # Start Tor process
        self._tor_process = subprocess.Popen(
            [tor_path, "-f", str(torrc_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for Tor to bootstrap
        await self._wait_for_bootstrap(timeout=timeout)

        return "127.0.0.1", self.socks_port
    
    async def _cleanup_tor(self) -> None:
        """Cleanup Tor process and temp directory without logging stop message."""
        if self._tor_process:
            self._tor_process.terminate()
            try:
                self._tor_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._tor_process.kill()
            self._tor_process = None

        if self._temp_dir:
            try:
                self._temp_dir.cleanup()
            except Exception:
                pass
            self._temp_dir = None

    async def _wait_for_bootstrap(self, timeout: int = 180) -> None:
        """Wait for Tor to finish bootstrapping by monitoring the log file."""
        import re
        
        logger.info("Waiting for Tor to bootstrap...", socks_port=self.socks_port)

        start_time = asyncio.get_event_loop().time()
        last_progress = 0
        last_progress_time = start_time
        log_position = 0
        stall_timeout = 60  # If no progress for 60s, consider it stalled

        while True:
            current_time = asyncio.get_event_loop().time()
            elapsed = current_time - start_time
            time_since_progress = current_time - last_progress_time
            
            # Check for overall timeout
            if elapsed > timeout:
                raise RuntimeError(f"Tor bootstrap timeout after {timeout}s (last progress: {last_progress}%)")
            
            # Check for stall - no progress for stall_timeout seconds
            if time_since_progress > stall_timeout and last_progress < 90:
                raise RuntimeError(f"Tor bootstrap stalled at {last_progress}% (no progress for {stall_timeout}s)")

            if self._tor_process.poll() is not None:
                stderr = self._tor_process.stderr.read().decode() if self._tor_process.stderr else ""
                raise RuntimeError(f"Tor process died: {stderr}")

            # Read from log file
            if hasattr(self, '_log_file') and self._log_file.exists():
                try:
                    with open(self._log_file, 'r') as f:
                        f.seek(log_position)
                        new_content = f.read()
                        log_position = f.tell()
                        
                        for line in new_content.splitlines():
                            # Look for bootstrap progress
                            if 'Bootstrapped' in line:
                                match = re.search(r'Bootstrapped (\d+)%', line)
                                if match:
                                    progress = int(match.group(1))
                                    if progress != last_progress:
                                        last_progress = progress
                                        last_progress_time = current_time  # Reset stall timer
                                        logger.info(f"Tor bootstrap: {progress}%")
                                    if progress >= 100:
                                        # Give it a moment to fully stabilize
                                        await asyncio.sleep(1)
                                        logger.info("Tor bootstrap complete", socks_port=self.socks_port)
                                        return
                            
                            # Check for error messages that indicate bridge issues
                            if 'WARN' in line and ('timeout' in line.lower() or 'failed' in line.lower()):
                                logger.debug(f"Tor warning: {line.strip()}")
                                
                except Exception as e:
                    logger.debug(f"Error reading log file: {e}")

            # Fallback: check if SOCKS port is actually working after some time
            if elapsed > 30:  # After 30s, try a connection test
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection("127.0.0.1", self.socks_port),
                        timeout=2.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    if last_progress >= 90:  # Accept 90% as good enough
                        logger.info("Tor bootstrap complete (connection test)", socks_port=self.socks_port)
                        return
                except (ConnectionRefusedError, asyncio.TimeoutError):
                    pass

            await asyncio.sleep(1)

    async def stop(self) -> None:
        """Stop Tor process and cleanup."""
        if self._tor_process:
            self._tor_process.terminate()
            try:
                self._tor_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._tor_process.kill()
            self._tor_process = None

        if self._temp_dir:
            self._temp_dir.cleanup()
            self._temp_dir = None

        logger.info("Tor with bridges stopped")


def get_bridge_preset(bridge_type: BridgeType) -> BridgeConfig:
    """Get a bridge configuration preset."""
    if bridge_type == BridgeType.NONE:
        return BridgeConfig(enabled=False)

    return BridgeConfig(
        enabled=True,
        bridge_type=bridge_type,
        use_builtin_bridges=True,
    )


def print_bridge_info(config: BridgeConfig) -> str:
    """Generate human-readable bridge configuration summary."""
    if not config.enabled:
        return "Bridges: Disabled (Tor connection may be detectable)"

    lines = [
        f"Bridge Type: {config.bridge_type.value.upper()}",
    ]

    if config.bridge_type == BridgeType.OBFS4:
        lines.append("  → Traffic looks like random noise")
        lines.append("  → Most effective against DPI")
    elif config.bridge_type == BridgeType.SNOWFLAKE:
        lines.append("  → Uses WebRTC peer connections")
        lines.append("  → Hard to block, uses volunteer proxies")

    if config.use_builtin_bridges:
        lines.append("Using: Built-in public bridges")
    else:
        lines.append(f"Using: {len(config.bridges)} custom bridge(s)")

    return "\n".join(lines)
