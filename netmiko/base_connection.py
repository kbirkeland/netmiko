'''
Base connection class for netmiko

Handles SSH connection and methods that are generically applicable to different
platforms (Cisco and non-Cisco).

Also defines methods that should generally be supported by child classes
'''

from __future__ import print_function
from __future__ import unicode_literals

import paramiko
import telnetlib
import time
import socket
import re
import io
import select
from os import path
from threading import Lock
from functools import wraps

from netmiko.netmiko_globals import MAX_BUFFER, BACKSPACE_CHAR
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from netmiko.utilities import write_bytes, check_serial_port, get_structured_data
from netmiko.py23_compat import string_types
from netmiko import log
import serial


class BaseConnection(object):
    """
    Defines vendor independent methods.

    Otherwise method left as a stub method.
    """
    def __init__(self, ip='', host='', username='', password='', secret='', port=None,
                 device_type='', verbose=False, use_keys=False,
                 key_file=None, allow_agent=False, ssh_strict=False, system_host_keys=False,
                 alt_host_keys=False, alt_key_file='', ssh_config_file=None, timeout=15,
                 session_timeout=60, keepalive=0, prompt_terminators=['>', '#']):
        """
        Initialize attributes for establishing connection to target device.

        :param ip: IP address of target device. Not required if `host` is
            provided.
        :type ip: str
        :param host: Hostname of target device. Not required if `ip` is
                provided.
        :type host: str
        :param username: Username to authenticate against target device if
                required.
        :type username: str
        :param password: Password to authenticate against target device if
                required.
        :type password: str
        :param secret: The enable password if target device requires one.
        :type secret: str
        :param port: The destination port used to connect to the target
                device.
        :type port: int or None
        :param device_type: Class selection based on device type.
        :type device_type: str
        :param verbose: Enable additional messages to standard output.
        :type verbose: bool
        :param use_keys: Connect to target device using SSH keys.
        :type use_keys: bool
        :param key_file: Filename path of the SSH key file to use.
        :type key_file: str
        :param allow_agent: Enable use of SSH key-agent.
        :type allow_agent: bool
        :param ssh_strict: Automatically reject unknown SSH host keys (default: False, which
                means unknown SSH host keys will be accepted).
        :type ssh_strict: bool
        :param system_host_keys: Load host keys from the user's 'known_hosts' file.
        :type system_host_keys: bool
        :param alt_host_keys: If `True` host keys will be loaded from the file specified in
                'alt_key_file'.
        :type alt_host_keys: bool
        :param alt_key_file: SSH host key file to use (if alt_host_keys=True).
        :type alt_key_file: str
        :param ssh_config_file: File name of OpenSSH configuration file.
        :type ssh_config_file: str
        :param timeout: Connection/command timeout.
        :type timeout: float
        :param session_timeout: Set a timeout for parallel requests.
        :type session_timeout: float
        :param keepalive: Send SSH keepalive packets at a specific interval, in seconds.
                Currently defaults to 0, for backwards compatibility (it will not attempt
                to keep the connection alive).
        :type keepalive: int
        :param prompt_terminators: Terminators found at the end of the prompt
        :type prompt_terminators: List[str]
        """
        self.remote_conn = None
        self.RETURN = '\n' if default_enter is None else default_enter
        self.TELNET_RETURN = '\r\n'
        # Line Separator in response lines
        self.RESPONSE_RETURN = '\n' if response_return is None else response_return
        if ip:
            self.host = ip
            self.ip = ip
        elif host:
            self.host = host
        if not ip and not host and 'serial' not in device_type:
            raise ValueError("Either ip or host must be set")
        if port is None:
            if 'telnet' in device_type:
                port = 23
            else:
                port = 22
        self.port = int(port)

        self.username = username
        self.password = password
        self.secret = secret
        self.device_type = device_type
        self.ansi_escape_codes = False
        self.verbose = verbose
        self.timeout = timeout
        self.session_timeout = session_timeout
        self.blocking_timeout = blocking_timeout
        self.keepalive = keepalive

        # Default values
        self.serial_settings = {
            'port': 'COM1',
            'baudrate': 9600,
            'bytesize': serial.EIGHTBITS,
            'parity': serial.PARITY_NONE,
            'stopbits': serial.STOPBITS_ONE
        }
        if serial_settings is None:
            serial_settings = {}
        self.serial_settings.update(serial_settings)

        if 'serial' in device_type:
            self.host = 'serial'
            comm_port = self.serial_settings.pop('port')
            # Get the proper comm port reference if a name was enterred
            comm_port = check_serial_port(comm_port)
            self.serial_settings.update({'port': comm_port})

        self.prompt_terminators = prompt_terminators

        # set in set_base_prompt method
        self.base_prompt = ''

        self.end = '\n'

        self._session_locker = Lock()

        # determine if telnet or SSH
        if '_telnet' in device_type:
            self.protocol = 'telnet'
            self.end = '\r\n'
            self._modify_connection_params()
            self.establish_connection()
            self.session_preparation()
        elif '_serial' in device_type:
            self.protocol = 'serial'
            self._modify_connection_params()
            self.establish_connection()
            self.session_preparation()
        else:
            self.protocol = 'ssh'

            if not ssh_strict:
                self.key_policy = paramiko.AutoAddPolicy()
            else:
                self.key_policy = paramiko.RejectPolicy()

            # Options for SSH host_keys
            self.use_keys = use_keys
            self.key_file = key_file
            self.allow_agent = allow_agent
            self.system_host_keys = system_host_keys
            self.alt_host_keys = alt_host_keys
            self.alt_key_file = alt_key_file

            # For SSH proxy support
            self.ssh_config_file = ssh_config_file

            self._modify_connection_params()
            self.establish_connection()
            self.session_preparation()

    def __enter__(self):
        """Establish a session using a Context Manager."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Gracefully close connection on Context Manager exit."""
        self.disconnect()

    def _modify_connection_params(self):
        """Modify connection parameters prior to SSH connection."""
        pass

    def _timeout_exceeded(self, start, msg='Timeout exceeded!'):
        """Raise NetMikoTimeoutException if waiting too much in the serving queue.

        :param start: Initial start time to see if session lock timeout has been exceeded
        :type start: float (from time.time() call i.e. epoch time)

        :param msg: Exception message if timeout was exceeded
        :type msg: str
        """
        if not start:
            # Must provide a comparison time
            return False
        if time.time() - start > self.session_timeout:
            # session_timeout exceeded
            raise NetMikoTimeoutException(msg)
        return False

    def _lock_netmiko_session(self, start=None):
        """Try to acquire the Netmiko session lock. If not available, wait in the queue until
        the channel is available again.

        :param start: Initial start time to measure the session timeout
        :type start: float (from time.time() call i.e. epoch time)
        """
        if not start:
            start = time.time()
        # Wait here until the SSH channel lock is acquired or until session_timeout exceeded
        while (not self._session_locker.acquire(False) and
               not self._timeout_exceeded(start, 'The netmiko channel is not available!')):
                time.sleep(.1)
        return True

    def _unlock_netmiko_session(self):
        """
        Release the channel at the end of the task.
        """
        if self._session_locker.locked():
            self._session_locker.release()

    def _write_channel(self, out_data):
        """Generic handler that will write to both SSH and telnet channel.

        :param out_data: data to be written to the channel
        :type out_data: str (can be either unicode/byte string)
        """
        if self.protocol == 'ssh':
            self.remote_conn.sendall(write_bytes(out_data))
        elif self.protocol == 'telnet':
            self.remote_conn.write(write_bytes(out_data))
        elif self.protocol == 'serial':
            self.remote_conn.write(write_bytes(out_data))
            self.remote_conn.flush()
        else:
            raise ValueError("Invalid protocol specified")
        log.debug("write_channel: {!r}".format(write_bytes(out_data)))

    def write_channel(self, out_data):
        """Generic handler that will write to both SSH and telnet channel.

        :param out_data: data to be written to the channel
        :type out_data: str (can be either unicode/byte string)
        """
        self._lock_netmiko_session()
        try:
            self._write_channel(out_data)
        finally:
            # Always unlock the SSH channel, even on exception.
            self._unlock_netmiko_session()

    def is_alive(self):
        """Returns a boolean flag with the state of the connection."""
        null = chr(0)
        if self.remote_conn is None:
            log.error("Connection is not initialised, is_alive returns False")
            return False
        if self.protocol == 'telnet':
            try:
                # Try sending IAC + NOP (IAC is telnet way of sending command
                # IAC = Interpret as Command (it comes before the NOP)
                log.debug("Sending IAC + NOP")
                self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
                return True
            except AttributeError:
                return False
        else:
            # SSH
            try:
                # Try sending ASCII null byte to maintain the connection alive
                log.debug("Sending the NULL byte")
                self.write_channel(null)
                return self.remote_conn.transport.is_active()
            except (socket.error, EOFError):
                log.error("Unable to send", exc_info=True)
                # If unable to send, we can tell for sure that the connection is unusable
                return False
        return False

    def _read_channel(self, timeout=None):
        """Generic handler that will read all the data from an SSH or telnet channel."""
        if timeout is None:
            timeout = self.timeout

        output = b''
        rfd, _, _ = select.select([self.remote_conn], [], [], timeout)
        while len(rfd) > 0:
            if self.protocol == 'ssh':
                obuf = self.remote_conn.recv(MAX_BUFFER)
            elif self.protocol == 'telnet':
                obuf = self.remote_conn.read_very_eager()
            else:
                raise ValueError('Invalid protocol {}'.format(self.protocol))

            if len(obuf) == 0:
                raise EOFError('Channel stream closed by remote device')

            output += obuf
            rfd, _, _ = select.select([self.remote_conn], [], [], 0.0)

        return output.decode('utf-8', 'ignore')

    def read_channel(self, timeout=None):
        """Generic handler that will read all the data from an SSH or telnet channel."""
        output = ""
        self._lock_netmiko_session()
        try:
            output = self._read_channel(timeout=timeout)
        finally:
            # Always unlock the SSH channel, even on exception.
            self._unlock_netmiko_session()
        log.debug('read_channel: {!r}'.format(output))
        return output

    def _read_channel_expect(self, pattern='', re_flags=0, timeout=None):
        """
        Function that reads channel until pattern is detected.

        pattern takes a regular expression.

        By default pattern will be self.base_prompt

        Note: this currently reads beyond pattern. In the case of SSH it reads MAX_BUFFER.
        In the case of telnet it reads all non-blocking data.

        There are dependencies here like determining whether in config_mode that are actually
        depending on reading beyond pattern.

        :param pattern: Regular expression pattern used to identify the command is done \
        (defaults to self.base_prompt)
        :type pattern: str (regular expression)

        :param re_flags: regex flags used in conjunction with pattern to search for prompt \
        (defaults to no flags)
        :type re_flags: re module flags

        :param max_loops: max number of iterations to read the channel before raising exception.
            Will default to be based upon self.timeout.
        :type max_loops: int

        """
        log.debug('expecting {!r}'.format(pattern))
        output = ''
        if not pattern:
            pattern = re.compile(self._prompt_pattern())
        else:
            pattern = re.compile(pattern, flags=re_flags)

        if not timeout:
            timeout = self.timeout

        last_time = time.time()

        last_time_delta = time.time() - last_time
        while last_time_delta < timeout:
            obuf = self.read_channel(timeout=(timeout - last_time_delta))
            output += obuf
            if pattern.search(output[output.rfind('\r'):]):
                return output
            if len(obuf) > 0:
                last_time = time.time()
            last_time_delta = time.time() - last_time
            time.sleep(0.001)

        log.debug('Timed out after {} seconds'.format(last_time_delta))

        raise NetMikoTimeoutException("Timed-out reading channel, pattern not found in output: {!r} {!r}"
                                      .format(pattern.pattern, output))

    def _read_channel_timing(self, timeout=None):
        """
        Read data on the channel based on timing delays.

        Attempt to read channel max_loops number of times. If no data this will cause a 15 second
        delay.

        Once data is encountered read channel for another two seconds to make
        sure reading of channel is complete.

        :param delay_factor: multiplicative factor to adjust delay when reading channel (delays
            get multiplied by this factor)
        :type delay_factor: int or float

        :param max_loops: maximum number of loops to iterate through before returning channel data.
            Will default to be based upon self.timeout.
        :type max_loops: int
        """
        output = self.read_channel(timeout=timeout)
        if len(output) > 0:
            output += self.read_channel(timeout=2)
        return output

    def read_until_prompt(self, *args, **kwargs):
        """Read channel until self.base_prompt detected. Return ALL data available."""
        return self._read_channel_expect(*args, **kwargs)

    def read_until_pattern(self, *args, **kwargs):
        """Read channel until pattern detected. Return ALL data available."""
        return self._read_channel_expect(*args, **kwargs)

    def read_until_prompt_or_pattern(self, pattern='', re_flags=0):
        """Read until either self.base_prompt or pattern is detected. Return ALL data available."""
        combined_pattern = self._prompt_pattern()
        if pattern:
            combined_pattern = r"({}|{})".format(combined_pattern, pattern)
        return self._read_channel_expect(combined_pattern, re_flags=re_flags)

    def serial_login(self, pri_prompt_terminator=r'#\s*$', alt_prompt_terminator=r'>\s*$',
                     username_pattern=r"(?:[Uu]ser:|sername|ogin)", pwd_pattern=r"assword",
                     delay_factor=1, max_loops=20):
        self.telnet_login(pri_prompt_terminator, alt_prompt_terminator, username_pattern,
                          pwd_pattern, delay_factor, max_loops)

    def telnet_login(self, username_pattern=r'sername', pwd_pattern=r'assword',
                     timeout=None):
        login_pattern = '({}|{})'.format(re.escape(username_pattern),
                                         re.escape(pwd_pattern))
        try:
            output = self._read_channel_expect(pattern=login_pattern)
            if username_pattern in output:
                output = self.send_command(self.username, expect_string=login_pattern)
            if pwd_pattern in output:
                output = self.send_command(self.password, auto_find_prompt=True)

            if not self.base_prompt:
                msg = 'Telnet authentication failed: {0}'.format(self.host)
                raise NetMikoAuthenticationException(msg)

            return output

        except (socket.error, EOFError):
            msg = 'Telnet login failed: {0}'.format(self.host)
            raise NetMikoAuthenticationException(msg)

    def session_preparation(self):
        """
        Prepare the session after the connection has been established

        This method handles some differences that occur between various devices
        early on in the session.

        In general, it should include:
        self._test_channel_read()
        self.set_base_prompt()
        self.disable_paging()
        self.set_terminal_width()
        self.clear_buffer()
        """
        self._test_channel_read()
        self.set_base_prompt()
        self.disable_paging()
        self.set_terminal_width()

        # Clear the read buffer
        time.sleep(.3 * self.global_delay_factor)
        self.clear_buffer()

    def _use_ssh_config(self, dict_arg):
        """Update SSH connection parameters based on contents of SSH 'config' file.

        :param dict_arg: Dictionary of SSH connection parameters
        :type dict_arg: dict
        """
        connect_dict = dict_arg.copy()

        # Use SSHConfig to generate source content.
        full_path = path.abspath(path.expanduser(self.ssh_config_file))
        if path.exists(full_path):
            ssh_config_instance = paramiko.SSHConfig()
            with io.open(full_path, "rt", encoding='utf-8') as f:
                ssh_config_instance.parse(f)
                source = ssh_config_instance.lookup(self.host)
        else:
            source = {}

        if source.get('proxycommand'):
            proxy = paramiko.ProxyCommand(source['proxycommand'])
        elif source.get('ProxyCommand'):
            proxy = paramiko.ProxyCommand(source['proxycommand'])
        else:
            proxy = None

        # Only update 'hostname', 'sock', 'port', and 'username'
        # For 'port' and 'username' only update if using object defaults
        if connect_dict['port'] == 22:
            connect_dict['port'] = int(source.get('port', self.port))
        if connect_dict['username'] == '':
            connect_dict['username'] = source.get('username', self.username)
        if proxy:
            connect_dict['sock'] = proxy
        connect_dict['hostname'] = source.get('hostname', self.host)

        return connect_dict

    def _connect_params_dict(self):
        """Generate dictionary of Paramiko connection parameters."""
        conn_dict = {
            'hostname': self.host,
            'port': self.port,
            'username': self.username,
            'password': self.password,
            'look_for_keys': self.use_keys,
            'allow_agent': self.allow_agent,
            'key_filename': self.key_file,
            'timeout': self.timeout,
        }

        # Check if using SSH 'config' file mainly for SSH proxy support
        if self.ssh_config_file:
            conn_dict = self._use_ssh_config(conn_dict)
        return conn_dict

    def _sanitize_output(self, output, strip_command=False, command_string=None,
                         strip_prompt=False):
        """Strip out command echo, trailing router prompt and ANSI escape codes.

        :param output: Output from a remote network device
        :type output: unicode string

        :param strip_command:
        :type strip_command:
        """
        if self.ansi_escape_codes:
            output = self.strip_ansi_escape_codes(output)
        output = self.normalize_linefeeds(output)
        if strip_command and command_string:
            command_string = self.normalize_linefeeds(command_string)
            output = self.strip_command(command_string, output)
        if strip_prompt:
            output = self.strip_prompt(output)
        return output

    def establish_connection(self, width=None, height=None):
        """
        Establish SSH connection to the network device

        Timeout will generate a NetMikoTimeoutException
        Authentication failure will generate a NetMikoAuthenticationException

        width and height are needed for Fortinet paging setting.
        """
        if self.protocol == 'telnet':
            self.remote_conn = telnetlib.Telnet(self.host, port=self.port, timeout=self.timeout)
            self.telnet_login()
        elif self.protocol == 'serial':
            self.remote_conn = serial.Serial(**self.serial_settings)
            self.serial_login()
        elif self.protocol == 'ssh':
            ssh_connect_params = self._connect_params_dict()
            self.remote_conn_pre = self._build_ssh_client()

            # initiate SSH connection
            try:
                self.remote_conn_pre.connect(**ssh_connect_params)
            except socket.error as e:
                msg = "Connection to device failed: {device_type} {ip}:{port} {reason}".format(
                    device_type=self.device_type, ip=self.host, port=self.port, reason=e)
                raise NetMikoTimeoutException(msg)
            except paramiko.ssh_exception.AuthenticationException as auth_err:
                msg = "Authentication failure: unable to connect {device_type} {ip}:{port}".format(
                    device_type=self.device_type, ip=self.host, port=self.port)
                msg += self.RETURN + str(auth_err)
                raise NetMikoAuthenticationException(msg)

            if self.verbose:
                print("SSH connection established to {0}:{1}".format(self.host, self.port))

            # Use invoke_shell to establish an 'interactive session'
            if width and height:
                self.remote_conn = self.remote_conn_pre.invoke_shell(term='vt100', width=width,
                                                                     height=height)
            else:
                self.remote_conn = self.remote_conn_pre.invoke_shell()

            self.remote_conn.settimeout(self.blocking_timeout)
            if self.keepalive:
                self.remote_conn.transport.set_keepalive(self.keepalive)
            self.special_login_handler()
            if self.verbose:
                print("Interactive SSH session established")
        return ""

    def _test_channel_read(self, count=40, pattern=""):
        """Try to read the channel (generally post login) verify you receive data back."""
        if len(self._read_channel_timing()) == 0:
            raise NetMikoTimeoutException("Timed out waiting for data")
        return ''

    def _build_ssh_client(self):
        """Prepare for Paramiko SSH connection."""
        # Create instance of SSHClient object
        remote_conn_pre = paramiko.SSHClient()

        # Load host_keys for better SSH security
        if self.system_host_keys:
            remote_conn_pre.load_system_host_keys()
        if self.alt_host_keys and path.isfile(self.alt_key_file):
            remote_conn_pre.load_host_keys(self.alt_key_file)

        # Default is to automatically add untrusted hosts (make sure appropriate for your env)
        remote_conn_pre.set_missing_host_key_policy(self.key_policy)
        return remote_conn_pre

    def special_login_handler(self):
        """Handler for devices like WLC, Avaya ERS that throw up characters prior to login."""
        pass

    def disable_paging(self, command="terminal length 0"):
        """Disable paging default to a Cisco CLI method."""
        return self.send_command(command)

    def set_terminal_width(self, command="", timeout=None):
        """
        CLI terminals try to automatically adjust the line based on the width of the terminal.
        This causes the output to get distorted when accessed programmatically.

        Set terminal width to 511 which works on a broad set of devices.
        """
        if not command:
            return ""
        return self.send_command(command, timeout=timeout)

    def set_base_prompt(self, timeout=None):
        """
        Sets self.base_prompt

        Uses self.prompt_terminators as delimiters for end of prompt

        This will be set on entering user exec or privileged exec on Cisco, but not when
        entering/exiting config mode.
        """
        self.base_prompt = self.find_prompt(timeout=timeout)
        return self.base_prompt

    def _prompt_pattern(self, prompt=None):
        """
        Returns the escaped regex pattern for prompt

        :param prompt: Prompt to search for. Defaults to self.base_prompt
        :type prompt: str
        """
        if prompt is None:
            prompt = self.base_prompt
        if len(self.prompt_terminators) > 0:
            return '\n{}.*[{}]'.format(re.escape(prompt), ''.join(self.prompt_terminators))
        return '\n{}'.format(re.escape(prompt))
        
    def _config_prompt_pattern(self):
        """
        Returns the escaped regex to search for config mode
        """
        return r'\(config[^\)]*\)'

    def _find_prompt(self, timeout=None):
        self.clear_buffer()
        prompt = self.send_command('', expect_string='\n[^\n]*({})'.format('|'.join(self.prompt_terminators)), timeout=timeout)
        if self.ansi_escape_codes:
            prompt = self.strip_ansi_escape_codes(prompt)
        return prompt.strip()

    def find_prompt(self, timeout=None):
        """Finds the current network device prompt, last line only."""
        # Find two consecutive prompts which are the same
        lprompt = self._find_prompt(timeout=timeout)
        for count in range(10):
            prompt = self._find_prompt(timeout=timeout)
            if lprompt == prompt:
                break
            lprompt = prompt

        # If multiple lines in the output take the last line
        prompt = self.normalize_linefeeds(prompt)
        prompt = prompt[max(0, prompt.rfind('\n')):]
        prompt = prompt.strip()
        if not prompt:
            raise ValueError("Unable to find prompt: {}".format(prompt))
        while prompt[-1] in self.prompt_terminators:
            prompt = prompt[:-1]
        return prompt

    def clear_buffer(self):
        """Read any data available in the channel."""
        self.read_channel(timeout=0)

    def send_command_timing(self, command_string, timeout=None,
                            strip_prompt=True, strip_command=True, normalize=True):
        """Execute command_string on the SSH channel using a delay-based mechanism. Generally
        used for show commands.

        :param command_string: The command to be executed on the remote device.
        :type command_string: str
        :param timeout: Controls wait time seconds (default: 15).
        :type timeout: int
        :param strip_prompt: Remove the trailing router prompt from the output (default: True).
        :type strip_prompt: bool
        :param strip_command: Remove the echo of the command from the output (default: True).
        :type strip_command: bool
        :param normalize: Ensure the proper enter is sent at end of command (default: True).
        :type normalize: bool
        :param use_textfsm: Process command output through TextFSM template (default: False).
        :type normalize: bool
        """
        output = ''
        self.clear_buffer()
        if normalize:
            command_string = self.normalize_cmd(command_string)

        self.write_channel(command_string)
        output = self._read_channel_timing(timeout=timeout)
        output = self._sanitize_output(output, strip_command=strip_command,
                                       command_string=command_string, strip_prompt=strip_prompt)
        if use_textfsm:
            output = get_structured_data(output, platform=self.device_type,
                                         command=command_string.strip())
        return output

    def strip_prompt(self, a_string):
        """Strip the trailing router prompt from the output."""
        if self.base_prompt in a_string[a_string.rfind('\n')-1:]:
            return a_string[:a_string.rfind('\n')]
        return a_string

    def send_command(self, command_string, expect_string=None,
                     timeout=None, auto_find_prompt=False,
                     strip_prompt=True, strip_command=True, normalize=True,
                     re_flags=0, end=None):
        """Execute command_string on the SSH channel using a pattern-based mechanism. Generally
        used for show commands. By default this method will keep waiting to receive data until the
        network device prompt is detected. The current network device prompt will be determined
        automatically.

        :param command_string: The command to be executed on the remote device.
        :type command_string: str

        :param expect_string: Regular expression pattern to use for determining end of output.
            If left blank will default to being based on router prompt.
        :type expect_str: str
        :param timeout: Controls wait time in seconds (default: self.timeout).
        :type timeout: int
        :param strip_prompt: Remove the trailing router prompt from the output (default: True).
        :type strip_prompt: bool

        :param strip_command: Remove the echo of the command from the output (default: True).
        :type strip_command: bool

        :param normalize: Ensure the proper enter is sent at end of command (default: True).
        :type normalize: bool
        :param re_flags: Flags to use when searching for pattern
        :type re_flags: str
        :param end: Newline character to append to the end (default: self.end)
        :type end: str
        """
        if auto_find_prompt:
            expect_string_arg = expect_string
            expect_string = self._prompt_pattern(prompt='')

        if end is None:
            end = self.end

        if normalize:
            command_string = self.normalize_cmd(command_string, end=end)

        self.write_channel(command_string)
        time.sleep(0.01)
        output = self._read_channel_expect(pattern=expect_string, re_flags=re_flags, timeout=timeout)
        output = self._sanitize_output(output, strip_command=strip_command,
                                       command_string=command_string, strip_prompt=strip_prompt)

        if auto_find_prompt:
            self.set_base_prompt()

        return output

    def send_command_expect(self, *args, **kwargs):
        """Support previous name of send_command method.

        :param args: Positional arguments to send to send_command()
        :type args: list

        :param kwargs: Keyword arguments to send to send_command()
        :type kwargs: Dict
        """
        return self.send_command(*args, **kwargs)

    @staticmethod
    def strip_backspaces(output):
        """Strip any backspace characters out of the output.

        :param output: Output obtained from a remote network device.
        :type output: str
        """
        backspace_char = '\x08'
        return output.replace(backspace_char, '')

    def strip_command(self, command_string, output):
        """
        Strip command_string from output string

        Cisco IOS adds backspaces into output for long commands (i.e. for commands that line wrap)
        """
        backspace_char = '\x08'

        # Check for line wrap (remove backspaces)
        if backspace_char in output:
            output = output.replace(backspace_char, '')
            return output[output.find('\n')+1:]
        else:
            command_length = len(command_string)
            return output[command_length:]

    @staticmethod
    def normalize_linefeeds(a_string):
        """Convert '\r\r\n','\r\n', '\n\r' to '\n."""
        newline = re.compile(r'\r*\n\r*')
        return newline.sub('\n', a_string)

    @staticmethod
    def normalize_cmd(command, end='\n'):
        """Normalize CLI commands to have a single trailing newline."""
        command = command.rstrip()
        command += end
        return command

    def check_enable_mode(self, check_string=''):
        """Check if in enable mode. Return boolean."""
        self.write_channel('\n')
        output = self.read_until_prompt()
        return check_string in output

    def enable(self, cmd='', pattern='assword', re_flags=re.IGNORECASE):
        """Enter enable mode."""
        output = ""
        msg = "Failed to enter enable mode. Please ensure you pass " \
              "the 'secret' argument to ConnectHandler."
        if not self.check_enable_mode():
            output = self.send_command(cmd, expect_string=pattern, re_flags=re_flags)
            #if pattern in output:
            if re.search(pattern, output, flags=re_flags):
                self.send_command(self.secret, auto_find_prompt=False)
            else:
                log.error('Failed to find pattern {!r} in output {!r}'.format(pattern, output))
            if not self.check_enable_mode():
                raise ValueError(msg)
        return output

    def exit_enable_mode(self, exit_command=''):
        """Exit enable mode."""
        output = ""
        if self.check_enable_mode():
            self.send_command(exit_command)
            if self.check_enable_mode():
                raise ValueError("Failed to exit enable mode.")
        return output

    def check_config_mode(self, check_string='', pattern=''):
        """Checks if the device is in configuration mode or not."""
        if not pattern:
            pattern = self._config_prompt_pattern()
        output = self.send_command('', expect_string=pattern, strip_prompt=False, strip_command=False, auto_find_prompt=False)
        return check_string in output

    def config_mode(self, config_command='', pattern=''):
        """Enter into config_mode."""
        if not pattern:
            pattern = self._config_prompt_pattern()
        output = ''
        if not self.check_config_mode():
            self.send_command(config_command, expect_string=pattern, strip_prompt=False, strip_command=False, auto_find_prompt=False)
            if not self.check_config_mode():
                raise ValueError("Failed to enter configuration mode.")
        log.debug('Entered config mode')
        return output

    def exit_config_mode(self, exit_config='', pattern=''):
        """Exit from configuration mode."""
        if not pattern:
            pattern = self._config_prompt_pattern()
        output = ''
        if self.check_config_mode():
            output = self.send_command(exit_config, expect_string=pattern, strip_prompt=False, strip_command=False, auto_find_prompt=True)
            if self.check_config_mode():
                raise ValueError("Failed to exit configuration mode")
        log.debug("exit_config_mode: {0}".format(output))
        return output

    def send_config_from_file(self, config_file=None, **kwargs):
        """
        Send configuration commands down the SSH channel from a file.

        The file is processed line-by-line and each command is sent down the
        SSH channel.

        **kwargs are passed to send_config_set method.
        """
        with io.open(config_file, "rt", encoding='utf-8') as cfg_file:
            return self.send_config_set(cfg_file, **kwargs)

    def send_config_set(self, config_commands=None, exit_config_mode=True,
                        timeout=None, strip_prompt=False, strip_command=False):
        """
        Send configuration commands down the SSH channel.

        config_commands is an iterable containing all of the configuration commands.
        The commands will be executed one after the other.

        Automatically exits/enters configuration mode.
        """
        pattern = self._config_prompt_pattern()
        if config_commands is None:
            return ''
        elif isinstance(config_commands, string_types):
            config_commands = (config_commands,)

        if not hasattr(config_commands, '__iter__'):
            raise ValueError("Invalid argument passed into send_config_set")

        # Send config commands
        cfg_mode_args = (config_mode_command,) if config_mode_command else tuple()
        output = self.config_mode(*cfg_mode_args)
        for cmd in config_commands:
            output += self.send_command(cmd, strip_prompt=False, strip_command=False, auto_find_prompt=False, expect_string=pattern, timeout=timeout)

        if exit_config_mode:
            output += self.exit_config_mode()
        return output

    def strip_ansi_escape_codes(self, string_buffer):
        """
        Remove any ANSI (VT100) ESC codes from the output

        http://en.wikipedia.org/wiki/ANSI_escape_code

        Note: this does not capture ALL possible ANSI Escape Codes only the ones
        I have encountered

        Current codes that are filtered:
        ESC = '\x1b' or chr(27)
        ESC = is the escape character [^ in hex ('\x1b')
        ESC[24;27H   Position cursor
        ESC[?25h     Show the cursor
        ESC[E        Next line (HP does ESC-E)
        ESC[K        Erase line from cursor to the end of line
        ESC[2K       Erase entire line
        ESC[1;24r    Enable scrolling from start to row end
        ESC[?6l      Reset mode screen with options 640 x 200 monochrome (graphics)
        ESC[?7l      Disable line wrapping
        ESC[2J       Code erase display
        ESC[00;32m   Color Green (30 to 37 are different colors) more general pattern is
                     ESC[\d\d;\d\dm and ESC[\d\d;\d\d;\d\dm
        ESC[6n       Get cursor position

        HP ProCurve's, Cisco SG300, and F5 LTM's require this (possible others)
        """
        code_next_line = chr(27) + r'E',           # code_next_line 

        output = string_buffer
        output = ANSI.code_regex.sub('', output)

        # CODE_NEXT_LINE must substitute with '\n'
        output = re.sub(ANSI.code_next_line, self.RETURN, output)

        return output

    def cleanup(self):
        """Any needed cleanup before closing connection."""
        pass

    def disconnect(self):
        """Try to gracefully close the SSH connection."""
        try:
            self.cleanup()
            if self.protocol == 'ssh':
                self.remote_conn_pre.close()
            elif self.protocol == 'telnet' or 'serial':
                self.remote_conn.close()
        except Exception:
            # There have been race conditions observed on disconnect.
            pass
        finally:
            self.remote_conn = None

    def commit(self):
        """Commit method for platforms that support this."""
        raise AttributeError("Network device does not support 'commit()' method")

    def save_config(self, cmd='', confirm=True, confirm_response=''):
        """Not Implemented"""
        raise NotImplementedError


class TelnetConnection(BaseConnection):
    pass

class ANSI:
    code_position_cursor = chr(27) + r'\[\d+;\d+H'
    code_show_cursor = chr(27) + r'\[\?25h'
    code_next_line = chr(27) + r'E'
    code_erase_line_end = chr(27) + r'\[K'
    code_erase_line = chr(27) + r'\[2K'
    code_erase_start_line = chr(27) + r'\[K'
    code_enable_scroll = chr(27) + r'\[\d+;\d+r'
    code_form_feed = chr(27) + r'\[1L'
    code_carriage_return = chr(27) + r'\[1M'
    code_disable_line_wrapping = chr(27) + r'\[\?7l'
    code_reset_mode_screen_options = chr(27) + r'\[\?\d+l'
    code_erase_display = chr(27) + r'\[2J'

    code_set = [code_position_cursor, code_show_cursor, code_erase_line, code_enable_scroll,
                code_erase_start_line, code_form_feed, code_carriage_return,
                code_disable_line_wrapping, code_erase_line_end,
                code_reset_mode_screen_options, code_erase_display]

    code_regex = re.compile('|'.join(code_set))
