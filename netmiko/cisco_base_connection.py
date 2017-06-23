"""CiscoBaseConnection is netmiko SSH class for Cisco and Cisco-like platforms."""
from __future__ import unicode_literals
from netmiko.base_connection import BaseConnection
from netmiko.ssh_exception import NetMikoAuthenticationException
import re
import time


class CiscoBaseConnection(BaseConnection):
    """Base Class for cisco-like behavior."""
    def check_enable_mode(self, check_string='#'):
        """Check if in enable mode. Return boolean."""
        return super(CiscoBaseConnection, self).check_enable_mode(check_string=check_string)

    def enable(self, cmd='enable', pattern='password', re_flags=re.IGNORECASE):
        """Enter enable mode."""
        return super(CiscoBaseConnection, self).enable(cmd=cmd, pattern=pattern, re_flags=re_flags)

    def exit_enable_mode(self, exit_command='disable'):
        """Exits enable (privileged exec) mode."""
        return super(CiscoBaseConnection, self).exit_enable_mode(exit_command=exit_command)

    def _config_prompt_pattern(self):
        """
        Cisco IOS devices abbreviate the prompt at 20 chars in config mode
        """
        return self._prompt_pattern(prompt=self.base_prompt[:15])

    def check_config_mode(self, check_string=')#', pattern=''):
        """
        Checks if the device is in configuration mode or not.
        """
        return super(CiscoBaseConnection, self).check_config_mode(check_string=check_string,
                                                                  pattern=pattern)

    def config_mode(self, config_command='config term', pattern=''):
        """
        Enter into configuration mode on remote device.

        """
        return super(CiscoBaseConnection, self).config_mode(config_command=config_command,
                                                            pattern=pattern)

    def exit_config_mode(self, exit_config='end', pattern=''):
        """Exit from configuration mode."""
        return super(CiscoBaseConnection, self).exit_config_mode(exit_config=exit_config,
                                                                 pattern=pattern)

    def telnet_login(self, username_pattern=r'sername', pwd_pattern=r'assword',
                     timeout=None):
        login_pattern = '({}|{})'.format(re.escape(username_pattern),
                                         re.escape_pwd_pattern)
        try:
            output = self._read_channel_expect(pattern=login_pattern)
            if username_pattern in output:
                output = send_command(self.username, expect_string=login_pattern)
            if pwd_pattern in output:
                output = self.send_command(self.password, auto_find_prompt=True)

            if self.base_prompt:
                return output

            if re.search(r"initial configuration dialog\? \[yes/no\]: ", output):
                output = self.send_command('no', expect_string=r'ress RETURN to get started', timeout=30)
                output = self.send_command('', auto_find_prompt=True)

            if re.search(r'assword required, but none set', output):
                msg = "Telnet login failed - Password required, but none set: {0}".format(
                        self.host)
                raise NetMikoAuthenticationException(msg)

            if not self.base_prompt:
                msg = 'Telnet login failed to find prompt: {0}'.format(self.host)
                raise NetMikoAuthenticationException(msg)

            return output

        except (socket.error, EOFError):
            msg = 'Telnet login failed: {0}'.format(self.host)
            raise NetMikoAuthenticationException(msg)

    def cleanup(self):
        """Gracefully exit the SSH session."""
        try:
            self.exit_config_mode()
        except Exception:
            # Always try to send 'exit' regardless of whether exit_config_mode works or not.
            pass
        self.write_channel("exit\n")

    def _autodetect_fs(self, cmd='dir', pattern=r'Directory of (.*)/'):
        """Autodetect the file system on the remote device. Used by SCP operations."""
        output = self.send_command_expect(cmd)
        match = re.search(pattern, output)
        if match:
            file_system = match.group(1)
            # Test file_system
            cmd = "dir {}".format(file_system)
            output = self.send_command_expect(cmd)
            if '% Invalid' not in output:
                return file_system

        raise ValueError("An error occurred in dynamically determining remote file "
                         "system: {} {}".format(cmd, output))


class CiscoSSHConnection(CiscoBaseConnection):
    pass
