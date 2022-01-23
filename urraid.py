#!/usr/bin/env python3
# urraid.py -*-python-*-
# Copyright 2021, 2022 by Rik Faith (rikfaith@users.noreply.github.com)
# This program comes with ABSOLUTELY NO WARRANTY.

import argparse
import concurrent.futures
import configparser
import multiprocessing
import inspect
import logging
import os
import queue
import re
import secrets
import select
import socket
import subprocess
import sys
import textwrap
import time
import traceback
import typing

# Imports that might have to be installed
try:
    import paramiko
except ImportError as e:
    print(f'''\
# Cannot load paramiko: {e}
# Consider: apt-get install python3-paramiko''')
    raise SystemExit from e


class Log():
    logger = None
    initial_level_set = False

    class LogFormatter(logging.Formatter):
        def __init__(self):
            logging.Formatter.__init__(self)

        def format(self, record):
            # pylint: disable=consider-using-f-string
            level = record.levelname[0]
            date = time.localtime(record.created)
            date_msec = (record.created - int(record.created)) * 1000
            stamp = '%c%04d%02d%02d %02d:%02d:%02d.%03d' % (
                level, date.tm_year, date.tm_mon, date.tm_mday,
                date.tm_hour, date.tm_min, date.tm_sec, date_msec)
            caller = inspect.getframeinfo(inspect.stack()[9][0])
            filename = '/'.join(caller.filename.split('/')[-2:])
            lineno = ' %s:%d' % (filename, caller.lineno)
            pid = ' %d' % os.getpid()
            message = '%s%s%s %s' % (stamp, lineno, pid,
                                     Log.format_message(record))
            record.getMessage = lambda: message
            return logging.Formatter.format(self, record)

    def __init__(self):
        Log.logger = logging.getLogger()
        logging.addLevelName(50, 'FATAL')
        handler = logging.StreamHandler()
        handler.setFormatter(Log.LogFormatter())
        Log.logger.addHandler(handler)
        Log.logger.setLevel(logging.INFO)

    @staticmethod
    def format_message(record):
        # pylint: disable=broad-except
        try:
            msg = record.msg % record.args
        except Exception as exception:
            msg = repr(record.msg) + \
                ' EXCEPTION: ' + repr(exception) + \
                ' record.msg=' + repr(record.msg) + \
                ' record.args=' + repr(record.args)
        return msg

    @staticmethod
    def fatal(message, *args, **kwargs):
        logging.fatal(message, *args, **kwargs)
        sys.exit(1)

    @staticmethod
    def setLevel(level):
        # We use setLevel instead of set_level because that's what logger
        # does. pylint: disable=invalid-name
        old_level = Log.logger.getEffectiveLevel()
        Log.logger.setLevel(level)
        return old_level


# Define global aliases to debugging functions.
DEBUG = logging.debug
INFO = logging.info
ERROR = logging.error
FATAL = Log.fatal
# Instantiate logging class
Log()


class Ssh():
    def __init__(self, remote, user, port=22, privkey=None, timeout=5):
        self.remote = remote
        self.user = user
        self.port = port
        self.privkey = privkey
        self.timeout = timeout

        self._parse_ssh_config()

        self.client = None
        if self.privkey is None:
            result = self._connect()
        else:
            result = self._connect_using_privkey()
        if result is not None:
            FATAL(result)

    def _parse_ssh_config(self):
        filename = os.path.expanduser('~/.ssh/config')
        if not os.path.exists(filename):
            return
        config = paramiko.config.SSHConfig.from_path(filename)
        info = config.lookup(self.remote)
        if info is None or len(info) == 0:
            return
        if 'hostname' in info:
            self.remote = info['hostname']
        if 'port' in info:
            self.port = info['port']
        if 'user' in info:
            self.user = info['user']

    def _connect(self):
        self.client = paramiko.client.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(
            paramiko.client.AutoAddPolicy())

        prefix = f'cannot ssh to {self.user}@{self.remote}:{self.port}: '

        # pylint: disable=broad-except
        try:
            self.client.connect(self.remote, username=self.user,
                                port=self.port, timeout=self.timeout)
        except paramiko.ssh_exception.PasswordRequiredException:
            return prefix + 'Invalid username, or password required'
        except Exception as exception:
            return prefix + str(exception)
        return None

    def _connect_using_privkey(self):
        self.client = paramiko.client.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(
            paramiko.client.AutoAddPolicy())

        prefix = f'cannot ssh to {self.user}@{self.remote}:{self.port}' + \
            ' using privkey: '

        # pylint: disable=broad-except
        try:
            self.client.connect(self.remote, username=self.user,
                                port=self.port, key_filename=self.privkey,
                                look_for_keys=False, allow_agent=False,
                                timeout=self.timeout)
        except paramiko.ssh_exception.PasswordRequiredException:
            return prefix + 'Invalid username, or password required'
        except Exception as exception:
            return prefix + str(exception)
        return None

    @staticmethod
    def _linesplit(channel, timeout=None, ending=None):
        channel.setblocking(0)
        start = time.time()
        buffer = ''
        while not channel.exit_status_ready():
            rlist, _, _ = select.select([channel], [], [], 1.0)
            if len(rlist) == 0:
                if timeout and time.time() - start > timeout:
                    break
                if ending and buffer.endswith(ending):
                    yield buffer
                    buffer = ''
                continue
            start = time.time()  # Restart timeout because we have data
            if len(rlist) > 0:
                try:
                    buffer += channel.recv(4096).decode('utf-8')
                except socket.timeout:
                    time.sleep(.1)
            while '\n' in buffer or '\r' in buffer:
                try:
                    line, buffer = re.split('[\r\n]+', buffer, 1)
                except ValueError:
                    yield re.sub(r'[\n\r]*', '', buffer)
                    buffer = ''
                    print('ValueError')
                    break
                yield line
        try:
            buffer += channel.recv_stderr(4096).decode('utf-8')
        except socket.timeout:
            time.sleep(.1)
        if buffer != '':
            yield buffer

    def execute(self, command, ending=None, prompt=None, data=None,
                output=None, timeout=None):
        # pylint: disable=broad-except
        if timeout is None:
            timeout = self.timeout
        result = []
        try:
            transport = self.client.get_transport()
            if transport is None:
                FATAL('Cannot get_transport()')
            channel = transport.open_session()
        except Exception as exception:
            FATAL(f'Cannot open session to {self.user}@{self.remote}: '
                  '{}'.format(repr(exception)))
        DEBUG(f'  {self.user}@{self.remote}: {command}')
        # Get a pty so that stderr will be combined with stdout. Otherwise, we
        # only get stderr if there is any output on stderr.
        if self.privkey is None:
            # Only get a pty if we have a normal shell on the remote.
            channel.get_pty()
        channel.exec_command(command)
        while not channel.exit_status_ready():
            for line in self._linesplit(channel, timeout=timeout,
                                        ending=ending):
                if output is not None:
                    output(line)
                if prompt is not None and re.search(prompt, line):
                    channel.send(data + '\n')
                    continue
                result.append(line)
        exit_status = channel.recv_exit_status()
        DEBUG(f'  exit_status={exit_status}')
        return result, exit_status


class Secret():
    def __init__(self, remote, local, user=None, timeout=5):
        self.remote = remote
        self.local = local
        self.user = user
        self.timeout = timeout
        self.helper = 'ursecret-helper.py'
        self.privkey = None
        self.pubkey = None
        self.ssh = None

    def _locate_key(self):
        dirname = os.path.expanduser('~/.ssh')
        with os.scandir(dirname) as scandir:
            for entry in scandir:
                if re.search(f'{self.remote}-ursecret-{self.local}',
                             entry.name) and entry.is_file():
                    if entry.name.endswith('.pub'):
                        self.pubkey = os.path.join(dirname, entry.name)
                    else:
                        self.privkey = os.path.join(dirname, entry.name)
        DEBUG(f'located {self.privkey}')

    def _connect(self, use_privkey=False):
        if use_privkey:
            self._locate_key()
            self.ssh = Ssh(self.remote, self.user, timeout=self.timeout,
                           privkey=self.privkey)
        else:
            self.ssh = Ssh(self.remote, self.user, timeout=self.timeout)

    def _find_key_type(self):
        result, status = self.ssh.execute('ssh -Q key')
        if status != 0:
            FATAL('cannot determine available key types')
        key_type = 'rsa'
        for line in result:
            if re.search(line, 'ssh-ed25519'):
                key_type = 'ed25519'
                return key_type  # This is the best, so return immediately
            if re.search(line, 'ecdsa', line):
                key_type = 'ecdsa'  # Keep looking for a better type
        return key_type

    def _generate_key(self):
        key_type = self._find_key_type()
        filename = os.path.join(os.path.expanduser('~/.ssh'),
                                f'{self.remote}-ursecret-{self.local}')
        if os.path.exists(filename) or os.path.exists(filename + '.pub'):
            FATAL(f'will not overwrite existing key in {filename}')
        current_time = time.strftime('%Y%m%d-%H%M%S')
        command = ['ssh-keygen',
                   '-f',
                   filename,
                   '-C',
                   f'{self.user}@{self.remote}-{self.local}-{current_time}',
                   '-N',
                   '']
        if key_type == 'rsa':
            command.extend(['-t', 'rsa', '-b', '4096'])
        elif key_type == 'ecdsa':
            command.extend(['-t', 'ecdsa', '-b', '521'])
        elif key_type == 'ed25519':
            command.extend(['-t', 'ed25519', '-a', '100'])
        else:
            FATAL(f'unknown key_type: {key_type}')
        INFO(f'generating key with: {" ".join(command)}')
        with subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:
            results = proc.communicate()[0]
            proc.wait()
        for result in results.split():
            DEBUG(result)
        self.privkey = filename
        self.pubkey = filename + '.pub'

    def _install_helper(self):
        helper = f'''#!/usr/bin/env python3
# {self.helper} -*-python-*-'''
        helper += '''
import os
import sys


class Secret():
    def __init__(self):
        self.dirname = os.path.expanduser('~/.ursecret')
        self.envname = 'SSH_ORIGINAL_COMMAND'

        if not os.path.isdir(self.dirname):
            os.mkdir(self.dirname, 0o700)

        if self.envname not in os.environ:
            self.fatal('invalid command')

        self.args = os.environ[self.envname].split()
        if len(self.args) <= 1:
            self.fatal('invalid command')

    def fatal(self, message):
        print('F: {}: {}'.format(message, self.args), file=sys.stderr)
        sys.exit(1)

    def get(self, key):
        filename = os.path.join(self.dirname, key)
        if not os.path.exists(filename):
            self.fatal('unknown key')
        with open(filename, 'r') as fp:
            value = fp.read()
        print(value)

    def put(self, key, value):
        filename = os.path.join(self.dirname, key)
        with open(filename, 'w') as fp:
            fp.write(value)
        print('I: key written to {}'.format(filename))

    def run(self):
        if self.args[0] == 'get':
            if len(self.args) != 2:
                self.fatal('illegal get')
            self.get(self.args[1])
        elif self.args[0] == 'put':
            if len(self.args) != 3:
                self.fatal('illegal put')
            self.put(self.args[1], self.args[2])
        else:
            self.fatal('illegal command')


if __name__ == '__main__':
    s = Secret()
    s.run()
    sys.exit(0)
'''

        INFO(f'installing {self.helper} on {self.remote}')
        with self.ssh.client.open_sftp() as ftp:
            file = ftp.file(f'.ssh/{self.helper}', 'w')
            file.write(helper)
            file.flush()
            ftp.chmod(f'.ssh/{self.helper}', 0o700)
        INFO(f'{self.helper} installed on {self.remote}')

    def _check_authorized_keys(self):
        result, status = self.ssh.execute('cat ~/.ssh/authorized_keys')
        if status != 0:
            return False
        for line in result:
            DEBUG(f'Read: {line}')
            if re.search(f'{self.helper}.*{self.remote}-{self.local}', line):
                return True
        return False

    def _install_key(self):
        INFO(f'installing key on {self.user}@{self.remote}')
        with self.ssh.client.open_sftp() as ftp:
            file = ftp.file('.ssh/authorized_keys', 'a')
            with open(self.pubkey, 'r', encoding='utf-8') as fp:
                for line in fp:
                    file.write(f'command="./.ssh/{self.helper}",'
                               'no-agent-forwarding,no-port-forwarding,no-pty,'
                               'no-user-rc,no-x11-forwarding ' + line)
            file.flush()

    def get_secret(self, key):
        self._connect(use_privkey=True)
        result, status = self.ssh.execute(f'get {key}')
        if status != 0:
            ERROR(f'could not get key={key}')
            for line in result:
                ERROR(f'{self.remote}: {line.strip()}')
            return ''
        value = None
        for line in result:
            value = line.strip()
            break
        return value

    def put_secret(self, key, value):
        self._connect(use_privkey=True)
        result, status = self.ssh.execute(f'put {key} {value}')
        if status != 0:
            ERROR(f'could not put key={key} value={value}')
            for line in result:
                ERROR(f'{self.remote}: {line.strip()}')

    def install(self):
        self._connect()
        self._install_helper()
        if self._check_authorized_keys():
            FATAL(f'key for {self.remote}-{self.local} found on '
                  f'{self.remote}: will not replace')
        INFO(f'no key for {self.remote}-{self.local} found on '
             f'{self.remote}: will install now')
        self._generate_key()
        self._install_key()


class Config():
    def __init__(self, paths=None):
        if paths is None:
            self.paths = ['~/.urraid',
                          '~/.config/urraid/config',
                          '/etc/urraid']
        else:
            if isinstance(paths, list):
                self.paths = paths
            else:
                self.paths = [paths]
        self.configs = []
        self._parse_configs()

    def _parse_configs(self):
        DEBUG(f'self.paths={self.paths}')
        for path in self.paths:
            filename = os.path.expanduser(path)
            if os.path.exists(filename):
                config = configparser.ConfigParser(allow_no_value=True)
                config.read(filename)
                self.configs.append(config)

    def _get_value(self, target, key):
        values_seen = set()
        values = []
        for config in self.configs:
            if target in config:
                value = config[target].get(key)
                if value is not None and value not in values_seen:
                    values.append(value)
                    values_seen.add(value)
        if values:
            return values
        return None

    def get_value(self, target, key, default=None):
        # Return value from section [target]
        value = self._get_value(target, key)
        if value:
            return value

        # Maybe implement a [default] section in the future?
        return default

    def dump(self):
        output = ''
        for config in self.configs:
            for section in config:
                output += f'\n[{section}]\n'
                for key, value in config[section].items():
                    if value is not None:
                        output += f'{key}={value}\n'
                    else:
                        output += f'{key}\n'
        return output


class Raid():
    # pylint: disable=invalid-name
    def __init__(self, name, remote, config, command, lvsvolume, devices,
                 mqueue, timeout=5):
        self.name = name
        self.remote = remote
        self.config = config
        self.command = command
        self.lvsvolume = lvsvolume
        self.devices = devices
        self.mqueue = mqueue
        self.timeout = timeout

        # For pylint, these must be defined in __init__
        self.drives = {}
        self.partitions = {}

        self.user = self.config.get_value(remote, 'username')
        if self.user is None:
            self.user = 'root'
        elif isinstance(self.user, list):
            self.user = self.user[0]

        self._clear_status()
        self.ssh = Ssh(self.remote, self.user, timeout=self.timeout)

    def INFO(self, message):
        self.mqueue.put((self.name, 'I', message))

    def FATAL(self, message) -> typing.NoReturn:
        self.mqueue.put((self.name, 'F', message))
        sys.exit(1)

    def _dump(self, result):
        for line in result:
            self.INFO(line)

    def _get_partitions(self):
        if len(self.partitions) > 0:
            return
        result, status = self.ssh.execute('cat /proc/partitions')
        if status:
            self.partitions = {}
            return
        for line in result:
            # Skip the header
            if line.startswith('major') or line == '':
                continue

            _, _, blocks, name = line.split()
            # Skip bogus partitions on the md devices
            if re.search(r'md\d+p\d+', name):
                continue

            if int(blocks) < 2:
                # Extended partitions are 1 block long
                continue
            self.partitions[os.path.join('/dev/', name)] = int(blocks) * 1024

    def _get_drives(self):
        if len(self.drives) > 0:
            return
        result, status = self.ssh.execute('lsscsi -bSS')
        if status:
            self.drives = {}
            return
        for line in result:
            _, dev, size = line.split()
            if dev == '-' or size == '-':
                continue
            blocks, block_size = size.split(',')
            size_bytes = int(blocks) * int(block_size)
            if size_bytes > 0:
                self.drives[dev] = size_bytes

    def _clear_status(self):
        self.uuid_devs = {}
        self.uuid_md = {}
        self.mds = set()
        self.encrypted = set()
        self.partitions = {}
        self.drives = {}
        self.mapping = {}
        self.sizes = {}
        self.level = {}
        self.provides = {}
        self.lvs = set()
        self.pvs = set()
        self.mounts = {}
        self.failed = {}

    def _get_status(self):
        self._clear_status()
        self._get_drives()
        self._get_partitions()
        DEBUG('determining device status')
        for dev in self.partitions:
            name = os.path.basename(dev)

            # For the non-md devices, determine the UUID of the md of the
            # associated md device, if applicable.
            result, _ = self.ssh.execute(f'mdadm -Q --examine {dev}')
            # Ignore the status so that we always get a --detail on md devices.
            for line in result:
                if re.search(r'Array UUID : ', line):
                    uuid = re.sub('.* UUID : ', '', line).strip()
                    if uuid not in self.uuid_devs:
                        self.uuid_devs[uuid] = []
                    self.uuid_devs[uuid].append(name)
                if re.search(r'Array Size : ', line):
                    size = re.sub('.* Size : ', '', line).strip()
                    size = re.sub(' .*$', '', size)
                    self.sizes[uuid] = (int(size) * 1024, '')
                if re.search(r'Raid Level : ', line):
                    level = re.sub('.* Level : ', '', line).strip()
                    self.level[uuid] = level

            # For all of the md devices, determine the UUID of the md.
            uuid = None
            result, status = self.ssh.execute(f'mdadm -Q --detail {dev}')
            if status:
                continue
            for line in result:
                if re.search(r'UUID : ', line):
                    uuid = re.sub('.* UUID : ', '', line).strip()
                    self.uuid_md[uuid] = name
                    self.mds.add(name)
                if uuid and re.search(r'Failed Devices :', line):
                    failed = re.sub('.* Devices : ', '', line).strip()
                    self.failed[uuid] = int(failed)

        DEBUG(f'found {len(self.uuid_devs)} UUIDs among'
              f' {len(self.partitions)} partitions')

        # Determine encryption status. If the header is detached, we can make
        # a determination from the uuid without the md device.
        DEBUG('determining encryption status')
        for uuid in self.uuid_devs:
            name = self.uuid_md.get(uuid)
            if name is not None:
                result, _ = self.ssh.execute(f'cryptsetup luksDump {name}')
                for line in result:
                    if re.search(r'LUKS header information', line):
                        self.encrypted.add(uuid)
                result, _ = self.ssh.execute(
                    f'cryptsetup luksDump --header "{uuid}.header" 0')
                for line in result:
                    if re.search(r'LUKS header information', line):
                        self.encrypted.add(uuid)

        # Determine volume mapping
        DEBUG('determining volume mapping')
        result, _ = self.ssh.execute('dmsetup deps -o devname')
        for line in result:
            if re.search(r'No devices', line):
                continue
            args = line.split()
            volume = None
            deps = []
            for arg in args:
                if volume is None:
                    volume = re.sub(r':', '', arg)
                elif arg[0] == '(':
                    deps.append(re.sub(r'[()]', '', arg))
            self.mapping[volume] = deps
            for dep in deps:
                self.provides[dep] = volume

        # Determine sizes
        DEBUG('determinging volume sizes')
        for volume in self.mapping:
            result, _ = self.ssh.execute(
                f'pvs --rows --units b /dev/mapper/{volume}')
            for line in result:
                if re.search(r'PSize', line):
                    _, size = line.split()
                    size = re.sub(r'B', '', size)
                    self.sizes[volume] = (size, '')
                    self.pvs.add(volume)
                if re.search(r'VG', line):
                    # Newer versions deactivate the VG on boot. Activate it
                    # here so that we can get VG status.
                    _, vg = line.split()
                    self.ssh.execute(f'vgchange -a y {vg}')

            if volume not in self.sizes:
                result, _ = self.ssh.execute(
                    f'lvs --rows --units b /dev/mapper/{volume}')
                for line in result:
                    if re.search(r'LSize', line):
                        _, size = line.split()
                        size = re.sub(r'B', '', size)
                        self.sizes[volume] = (size, '')
                        self.lvs.add(volume)

        # Determine what is mounted
        DEBUG('determining mount status')
        result, _ = self.ssh.execute(
            'df -B1 --output=source,target,fstype,size,used')
        for line in result:
            if line.startswith('/dev/mapper'):
                volume, mountpoint, fstype, size, used = line.split()
                volume = re.sub(r'/dev/mapper/', '', volume)
                self.mounts[volume] = (mountpoint, fstype)
                self.sizes[mountpoint] = (size, used)

    def _get_next_mdname(self):
        for i in range(0, 10):
            name = f'md{i}'
            if name not in self.mds:
                return name
        self.FATAL('More than 10 md devices not supported')

    def _get_next_volname(self):
        for i in range(0, 10):
            name = f'r{i}'
            if name not in self.mapping:
                return name
        self.FATAL('More than 10 volumes not supported')

    @staticmethod
    def _human(size, metric=False):
        if size == '':
            return ''
        size = int(size)
        if metric:
            divisor = 1000
            units = ['b', 'KB', 'MB', 'GB', 'TB']
        else:
            divisor = 1024
            units = ['b', 'KiB', 'MiB', 'GiB', 'TiB']
        unit = 0
        while size > divisor and unit < len(units) - 1:
            size /= divisor
            unit += 1
        return f'{size:.2f}{units[unit]}'

    def _md5up(self):
        self._get_status()
        # Bring up md devices
        for uuid in self.uuid_devs:
            if uuid in self.uuid_md:
                self.INFO(f'up: {self.uuid_md[uuid]} {uuid}')
                continue
            name = self._get_next_mdname()
            self.INFO(f'starting: {name} {uuid}')
            result, _ = self.ssh.execute(f'mdadm -A --uuid {uuid} {name}')
            self._dump(result)

    def _md5down(self):
        self._get_status()
        for uuid in self.uuid_devs:
            name = self.uuid_md.get(uuid)
            if name is None:
                self.INFO(f'down: {uuid}')
                continue
            self.INFO(f'stopping: {name} {uuid}')
            dev = os.path.join("/dev/", name)
            result, _ = self.ssh.execute(f'mdadm -S {dev}')
            self._dump(result)

    def _md5create(self, partitions, level=6):
        name = self._get_next_mdname()
        result, status = self.ssh.execute(
            f'mdadm -C /dev/{name} --verbose -n {len(partitions)} -l {level}'
            f' {" ".join(partitions)}',
            prompt='Continue creating array?',
            data='YES')
        self._dump(result)
        if status != 0:
            self.FATAL('cannot create {name}')

        self.INFO('setting stripe_cache_size')
        result, status = self.ssh.execute(
            f'echo 32768 > /sys/block/{name}/md/stripe_cache_size')
        self._dump(result)
        if status != 0:
            self.FATAL('could not set stripe_cache_size')

        self.INFO('updating /etc/mdadm/mdadm.conf')
        result, status = self.ssh.execute('/usr/share/mdadm/mkconf')
        if status != 0:
            self.FATAL('cannot run /usr/share/mdadm/mkconf')
        for line in result:
            if line.startswith('ARRAY'):
                _, _, meta, uuid, name = line.split()
                _, status = self.ssh.execute(
                    f'echo "ARRAY <ignore> {meta} {uuid} {name}"'
                    ' >> /etc/mdadm/mdadm.conf')
                if status != 0:
                    self.FATAL('could not update /etc/mdadm/mdadm.conf')

        self.INFO('updating initramfs')
        result, status = self.ssh.execute('update-initramfs -u')
        self._dump(result)
        if status != 0:
            self.FATAL('cannot update initramfs')

        return name

    def _create_luks_header(self, uuid):
        _, status = self.ssh.execute(f'test -f {uuid}.header')
        if not status:
            self.FATAL(f'{uuid}.header already exists on {self.remote}')
            return
        self.INFO(f'creating {uuid}.header on {self.remote}')
        result, _ = self.ssh.execute(
            f'dd if=/dev/zero of={uuid}.header bs=4k count=1024')
        self._dump(result)

    def _luksformat(self):
        for uuid, name in self.uuid_md.items():
            luks_key = self._get_luks_key(uuid)
            if luks_key != '':
                self.FATAL(f'LUKS key already exists for {name} {uuid}')
                continue

            self._create_luks_header(uuid)

            self.INFO(f'creating LUKS key for {name} {uuid}')
            for key in ['key0', 'key1', 'key2', 'key3']:
                key_remote = self.config.get_value(self.remote, key)
                if key_remote is not None and len(key_remote) > 0:
                    secret = Secret(key_remote[0], socket.gethostname(),
                                    self.user)
                    partial = secrets.token_hex(64)
                    secret.put_secret(uuid, partial)
            luks_key = self._get_luks_key(uuid)
            if luks_key == '':
                self.FATAL('unable to store LUKS key, check ~/.urraid')

            result, _ = self.ssh.execute(
                f'cryptsetup luksFormat /dev/{name} '
                f'--header "{uuid}.header" --use-random --batch-mode',
                prompt='passphrase', data=luks_key)
            self._dump(result)
            self.INFO(f'finished formatting {name} {uuid}')
            return uuid, name
        return None, None

    def _lvscreate(self, uuid, name):
        self._get_status()
        self.INFO(f'creating pvs/lvs state for {name} {uuid}')
        if name not in self.provides:
            self.FATAL(f'cannot find volume for {name}')
        volume = self.provides[name]
        result, _ = self.ssh.execute(f'pvcreate /dev/mapper/{volume}')
        self._dump(result)
        result, _ = self.ssh.execute(f'pvs /dev/mapper/{volume} -o+pe_start')
        self._dump(result)
        vg, mountpoint = self.lvsvolume.split('-')
        result, _ = self.ssh.execute(
            f'vgcreate -s 1g {vg} /dev/mapper/{volume}')
        self._dump(result)
        result, _ = self.ssh.execute(
            f'lvcreate -l "100%FREE" -n {mountpoint} {vg}')
        self._dump(result)
        self.INFO(f'lvs volume {self.lvsvolume} created on {vg}')

    def _luksopen(self):
        # Bring up LUKS devices
        self._get_status()
        for uuid, name in self.uuid_md.items():
            if name in self.provides:
                self.INFO(f'decrypted: {name} {uuid} as {self.provides[name]}')
                continue
            volume = self._get_next_volname()
            self.INFO(f'decrypting {name} {uuid} as {volume}')
            luks_key = self._get_luks_key(uuid)
            if luks_key == '':
                self.INFO(f'cannot determine LUKS key for {uuid}')
                continue
            _, exit_status = self.ssh.execute(
                f'cryptsetup luksOpen /dev/{name} '
                f'--header "{uuid}.header" {volume}',
                prompt='passphrase', data=luks_key, ending=':',
                output=self.INFO, timeout=20)
            if exit_status == 0:
                self.INFO(f'finished decrypting {name} {uuid} as {volume}')
            else:
                self.FATAL(f'could not decrypt {name}: {exit_status}')

    def _luksclose(self):
        self._get_status()
        for pvs in self.pvs:
            path = os.path.join('/dev/mapper', pvs)
            self.INFO(f'closing {path}')
            result, _ = self.ssh.execute(f'cryptsetup luksClose {path}')
            self._dump(result)
            self.INFO(f'finished closing {path}')

    def _lvchange(self, on=False):
        self._get_status()
        for lvs in self.lvs:
            path = os.path.join('/dev/mapper', lvs)
            if on:
                self.INFO(f'activating {path}')
                result, _ = self.ssh.execute(f'lvchange -ay {path}')
                self.INFO(f'finished activating {path}')
            else:
                self.INFO(f'deactivating {path}')
                result, _ = self.ssh.execute(f'lvchange -an {path}')
                self.INFO(f'finished deactivating {path}')
            self._dump(result)

    def _mount(self):
        self._get_status()
        for lvs in self.lvs:
            if lvs in self.mounts:
                mountpoint, fstype = self.mounts[lvs]
                self.INFO(f'mounted: {lvs} {mountpoint} {fstype}')
                continue
            path = os.path.join('/dev/mapper', lvs)

            # Do fsck
            self.INFO(f'checking {path}')
            self.ssh.execute(f'e2fsck -f -y {path}', output=self.INFO,
                             timeout=600)
            self.INFO(f'checked: {path}')

            # Mount
            _, lv = lvs.split('-', 1)
            mountpoint = f'/{lv}'
            if not os.path.exists(mountpoint):
                result, _ = self.ssh.execute(f'mkdir {mountpoint}')
                self._dump(result)
            DEBUG('mounting {path} on {mountpoint}')
            result, _ = self.ssh.execute(
                f'mount -onoatime,nodiratime {path} {mountpoint}')
            self._dump(result)
            self.INFO(f'finished mounting {path} on {mountpoint}')

    def _umount(self):
        self._get_status()
        for _, (mountpoint, _) in self.mounts.items():
            self.INFO(f'umounting {mountpoint}')
            result, _ = self.ssh.execute(f'umount {mountpoint}')
            self._dump(result)
            self.INFO(f'finished umounting {mountpoint}')

    def _services(self, start=False):
        for service in ['rpcbind', 'nfs-kernel-server', 'rsync']:
            if start:
                result, _ = self.ssh.execute(f'/etc/init.d/{service} start',
                                             output=self.INFO, timeout=60)
            else:
                result, _ = self.ssh.execute(f'/etc/init.d/{service} stop')
            self._dump(result)

    def _get_luks_key(self, uuid):
        # pylint: disable=broad-except
        luks_key = ''
        for key in ['key0', 'key1', 'key2', 'key3']:
            key_remote = self.config.get_value(self.remote, key)
            if key_remote is not None and len(key_remote) > 0:
                try:
                    secret = Secret(key_remote[0], socket.gethostname(),
                                    self.user)
                    luks_key += secret.get_secret(uuid)
                except Exception:
                    pass
        return luks_key

    def _rightsize(self, size):
        '''
        Historic data is as follows:
        8TB drives, size = 7630885, rightsize = 7630880, loss=6
        6TB drives, size = 5723167, rightsize = 5723164, loss=3
        5TB drives, size = 4769307, rightsize = 4769300, loss=7
        4TB drives, size = 3815448, rightsize = 3815400, loss=48
                    on char: 3815440
        3TB drives, size = 2861588, rightsize = 2861536, loss=52
                    previously: 2861588 and 2861312
        2TB drives, size = 1907729, rightsize = 1907711
        1TB drives, size = 953868 , rightsize = 953864, loss=4

        The goal moving forward is to return a value in MiB that is
        smaller than the current size, but that is a multiple of 8.
        '''
        tb = int(size / 1000**4 + .5)
        if tb == 1:
            return 953864
        if tb == 2:
            return 1907711
        if tb == 3:
            return 2861536
        if tb == 4:
            return 3815400
        if tb == 5:
            return 4769300
        if tb == 6:
            return 5723164
        if tb == 8:
            return 7630880
        if tb == 12:
            return 11444216

        mb = int(size / 1024)
        mb = int(mb / 1024)
        mb = int((mb-1) / 8) * 8
        self.FATAL(f'Cannot rightsize {size} bytes == {tb}TB, suggest {mb}')

    def _partition(self, dev, rightsize):
        self.INFO(f'creating gpt label on {dev}')
        result, status = self.ssh.execute(f'parted -s {dev} mklabel gpt')
        self._dump(result)
        if status != 0:
            self.FATAL(f'cannot create gpt label on {dev}')

        self.INFO(f'creating {rightsize}MiB partition on {dev}')
        result, status = self.ssh.execute(
            f'parted -s {dev} -- unit mib mkpart primary ext4 1 {rightsize}')
        self._dump(result)
        if status != 0:
            self.FATAL(f'cannot create partition on {dev}')

        self.INFO(f'setting raid flag on partition 1 of {dev}')
        result, status = self.ssh.execute(f'parted -s {dev} set 1 raid on')
        self._dump(result)
        if status != 0:
            self.FATAL(f'could not set raid flag on partition 1 of {dev}')

        result, _ = self.ssh.execute(f'parted -s {dev} -- unit mib print')
        self._dump(result)
        self.INFO(f'{dev} partitioned')

    def status(self):
        self._get_status()
        # Report on drives
        for dev, size in self.drives.items():
            self.INFO(f'{os.path.basename(dev):10s}'
                      f' {self._human(size, metric=True):>28s}'
                      f' = {self._human(size):>10s}')

        # Report on partitions
        for part, size in sorted(self.partitions.items()):
            if not re.search(r'\d$', part):
                continue
            self.INFO(f'{os.path.basename(part):10s}'
                      f' {self._human(size, metric=True):>28s}'
                      f' = {self._human(size):>10s}')

        # Report md devices
        for uuid, devs in self.uuid_devs.items():
            devs = ' '.join(sorted(devs))
            md = self.uuid_md.get(uuid, '')
            size, _ = self.sizes.get(uuid, ('', ''))
            size = self._human(size)
            level = self.level.get(uuid, '')
            failed = self.failed.get(uuid, 0)
            self.INFO(
                f'{md:5s} {uuid:35s} {size:>10s} {level:6s} {failed} {devs}')

            if failed > 0:
                self.INFO(f'{uuid:41s} {failed} device(s) FAILED **********')

        # Report volume mappings
        for volume, deps in self.mapping.items():
            deps = ' '.join(sorted(deps))
            size, _ = self.sizes.get(volume, ('', ''))
            size = self._human(size)
            self.INFO(f'{volume:41s} {size:>10s} {deps}')
        # Report mounts
        for volume, (mountpoint, fstype) in self.mounts.items():
            size, used = self.sizes.get(mountpoint, ('', ''))
            free = self._human(int(size) - int(used))
            size = self._human(size)
            self.INFO(f'{mountpoint:25s} free={free:>10s} {size:>10s}'
                      f' {fstype:6s} {volume}')

    def up(self):
        DEBUG('bringing services down')
        self._services(start=False)
        DEBUG('bringing md devices up')
        self._md5up()
        DEBUG('opening LUKS devices')
        self._luksopen()
        DEBUG('changing LV status')
        self._lvchange(on=True)
        DEBUG('mounting')
        self._mount()
        DEBUG('bringing services up')
        self._services(start=True)
        DEBUG('up complete')
        self.status()

    def down(self):
        DEBUG('bringing services down')
        self._services(start=False)
        DEBUG('unmounting')
        self._umount()
        DEBUG('changing LV status')
        self._lvchange(on=False)
        DEBUG('closing LUKS devices')
        self._luksclose()
        DEBUG('down complete')
        self.status()

    def create(self):
        self._services(start=False)
        self._md5up()
        uuid, name = self._luksformat()
        self._luksopen()
        self._lvscreate(uuid, name)
        self.down()
        self.up()
        self.INFO(f'manually run mke2fs {self.lvsvolume}')

    def partition(self):
        self.status()
        size = 0
        for dev in self.devices.split(','):
            if dev not in self.drives:
                self.FATAL('{dev} does not exist')
            if size == 0:
                size = self.drives[dev]
            if size != self.drives[dev]:
                self.FATAL(f'{dev} has unexpected size: '
                           f'{self.drives[dev]} instead of {size}')
        rightsize = self._rightsize(size)
        self.INFO(f'Rightsizing {size} to {rightsize}')
        for dev in self.devices.split(','):
            self._partition(dev, rightsize)

    def make_raid(self):
        self.status()
        size = 0
        partitions = []
        for part in self.devices.split(','):
            partitions.append(part)
            if part not in self.partitions:
                self.FATAL(f'{part} does not exist')
            if not re.search(r'\d$', part):
                self.FATAL(f'{part} must specify a partition, not a drive')
            if size == 0:
                size = self.partitions[part]
            if size != self.partitions[part]:
                self.FATAL(f'{part} has unexpected size: '
                           f'{self.partitions[part]} instead of {size}')
        self.INFO(f'creating raid using {len(partitions)} partitions of size'
                  f' {self._human(size,metric=True)}')
        name = self._md5create(partitions)
        self.INFO(f'created {name} using {len(partitions)} partitions')

    def run(self):
        if self.command == 'status':
            self.status()
        elif self.command == 'up':
            self.up()
        elif self.command == 'down':
            self.down()
        elif self.command == 'CREATE':
            self.create()
        elif self.command == 'PARTITION':
            self.partition()
        elif self.command == 'MAKERAID':
            self.make_raid()
        else:
            self.FATAL(f'Illegal command: {self.command}')


class Pool():
    def __init__(self, remote_list, config, command, lvsvolume=None,
                 devices=None, max_workers=4, timeout=5):
        self.remote_list = remote_list
        self.config = config
        self.command = command
        self.lvsvolume = lvsvolume
        self.devices = devices
        self.max_workers = max_workers
        self.timeout = timeout

    @staticmethod
    def _worker(name, remote, config, command, lvsvolume, devices, mqueue,
                timeout=5):
        try:
            raid = Raid(name, remote, config, command, lvsvolume, devices,
                        mqueue, timeout=timeout)
            raid.run()
        except Exception as exception:
            raise Exception(
                ''.join(traceback.format_exception(*sys.exc_info()))) \
                from exception

    @staticmethod
    def _done_callback(name, future):
        exc = future.exception()
        if exc is not None:
            ERROR('%s: future.exception=%s', name, str(exc))
            return

        result = future.result()
        if result is not None:
            ERROR('%s: future.result=%s', name, str(future.result()))

    def run(self):
        jobs = {}
        manager = multiprocessing.Manager()
        mqueue = manager.Queue()

        with concurrent.futures.ProcessPoolExecutor(
                max_workers=self.max_workers) as executor:
            for remote in self.remote_list:
                # Create a unique name in case a remote is listed twice
                idx = 1
                name = remote
                while remote in jobs:
                    name = remote + '-' + str(idx)
                    idx += 1

                future = executor.submit(
                    self._worker,
                    name,
                    remote,
                    self.config,
                    self.command,
                    self.lvsvolume,
                    self.devices,
                    mqueue)
                jobs[name] = future

                future.add_done_callback(lambda future, name=name:
                                         self._done_callback(name, future))

            running = True
            while running:
                try:
                    name, mtype, message = mqueue.get(False)
                    if mtype == 'F':
                        FATAL('%s: %s', name, message)
                    else:
                        INFO('%s: %s', name, message)
                except queue.Empty:
                    running = False
                    for name, future in jobs.items():
                        running |= future.running()
                    time.sleep(1)

            while not mqueue.empty():
                name, mtype, message = mqueue.get(False)
                if mtype == 'F':
                    FATAL('%s: %s', name, message)
                else:
                    INFO('%s: %s', name, message)


def confirm(message):
    result = input(message)
    if result == 'YES':
        return True
    return False


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='Configure, start, and stop remote data stores',
        epilog=textwrap.dedent('''

        Low-level manipulation of keys using --install, --get, and --put
        do NOT specify a COMMAND. The TARGET in these cases is the remote
        that is storing the key; NOT the remote that contains the storage.

        High-level Storage Commands:

        status: obtain status
        up: bring up data store
        down: shut down data store
        PARTITION: add gpt partition to a set of disk drives
        MAKERAID: create an md raid from a set of partitions
        CREATE: generate keys and store them as specified in ~/.urraid,
                format LUKS encrypted volume on an md raid,
                create an LVS volume with the specified name

        All UPPERCASE commands are DESTRUCTIVE and require:
          1) an interactive response from the console; and
          2) may only be run against a single target.'''))
    parser.add_argument('target', type=str, nargs='?',
                        help='target host or comma separated list of hosts')
    parser.add_argument('command', type=str, nargs='?',
                        help='command (status|up|down|'
                        'CREATE|PARTITION|MAKERAID)')
    parser.add_argument('--lvsvolume', type=str,
                        help='name of LVS volume for CREATE, e.g., v0-data')
    parser.add_argument('--devices', type=str,
                        help='comma-separated list for PARTITION, MAKERAID,\n'
                        'e.g., /dev/sdb,/dev/sdc or /dev/sdb1,/dev/sdc1')
    parser.add_argument('--partitions', type=str,
                        help='comma-separated list for MAKERAID,\n'
                        'e.g., /dev/sdb1,/dev/sdc1')
    parser.add_argument('--config', default=None,
                        help='configuration file')
    parser.add_argument('--dump', action='store_true', default=False,
                        help='dump config file and exit')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='verbose debugging output')
    parser.add_argument('--install', action='store_true', default=False,
                        help='install ssh key between localhost and TARGET')
    parser.add_argument('--get', type=str, default=None,
                        help='get named secret from TARGET', metavar='KEY')
    parser.add_argument('--put', type=str, default=None, nargs=2,
                        help='put named secret to TARGET',
                        metavar=('KEY', 'VALUE'))
    args = parser.parse_args()

    logging.getLogger('paramiko').setLevel(logging.WARNING)
    if args.debug:
        Log.logger.setLevel(logging.DEBUG)
        logging.getLogger('paramiko').setLevel(logging.INFO)

    config = Config(args.config)
    if args.dump:
        INFO(f'config={config.dump()}')
        sys.exit(0)

    target_list = []
    if args.target:
        if re.search(',', args.target):
            target_list = args.target.split(',')
        else:
            target_list = [args.target]

    if args.install:
        if len(target_list) > 1 or args.command or args.get or args.put:
            parser.print_help()
            sys.exit(1)
        secret = Secret(target_list[0], socket.gethostname(),
                        user=config.get_value(target_list[0], 'username',
                                              'root'))
        secret.install()
        sys.exit(0)

    if args.put:
        if len(target_list) > 1 or args.command or args.install or args.get:
            parser.print_help()
            sys.exit(1)
        secret = Secret(target_list[0], socket.gethostname(),
                        user=config.get_value(target_list[0], 'username',
                                              'root'))
        secret.put_secret(*args.put)
        sys.exit(0)

    if args.get:
        if len(target_list) > 1 or args.command or args.install or args.put:
            parser.print_help()
            sys.exit(1)
        secret = Secret(target_list[0], socket.gethostname(),
                        user=config.get_value(target_list[0], 'username',
                                              'root'))
        INFO(f'secret: {secret.get_secret(args.get)}')
        sys.exit(0)

    if args.target is None or args.command is None or args.command not in [
            'status', 'up', 'down', 'CREATE', 'PARTITION', 'MAKERAID']:
        parser.print_help()
        sys.exit(1)

    if args.command == 'CREATE':
        if not args.lvsvolume or len(target_list) > 1:
            parser.print_help()
            sys.exit(1)
        result = confirm(f'Destroy data on {args.lvsvolume}: YES or no? ')
        if not result:
            FATAL('No action taken -- must type "YES" to confirm')

    if args.command == 'PARTITION':
        if not args.devices or len(target_list) > 1:
            parser.print_help()
            sys.exit(1)

        result = confirm(f'Destroy data on {args.devices}: YES or no? ')
        if not result:
            FATAL('No action taken -- must type "YES" to confirm')

    if args.command == 'MAKERAID':
        if not args.devices or len(target_list) > 1:
            parser.print_help()
            sys.exit(1)

        result = confirm(f'Destroy data on {args.devices}: YES or no? ')
        if not result:
            FATAL('No action taken -- must type "YES" to confirm')

    pool = Pool(target_list, config, args.command, lvsvolume=args.lvsvolume,
                devices=args.devices)
    pool.run()


if __name__ == '__main__':
    main()
    sys.exit(0)
