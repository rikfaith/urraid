#!/usr/bin/env python3
# urraid.py -*-python-*-
# Copyright 2021 by Rik Faith (rikfaith@users.noreply.github.com)
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
import sys
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

sys.path.insert(1, os.path.join(sys.path[0], '../ursecret'))
try:
    import ursecret
except ImportError as e:
    print(f'''\
# Cannot load ursecret: {e}
# sys.path={sys.path}''')
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
    def __init__(self, remote, user, debug=False, timeout=5):
        self.remote = remote
        self.user = user
        self.debug = debug
        self.timeout = timeout

        self.client = None
        result = self._connect(self.user)
        if result is not None:
            FATAL(result)

    def _connect(self, user):
        # pylint: disable=broad-except
        self.client = paramiko.client.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(
            paramiko.client.AutoAddPolicy())

        prefix = 'Cannot ssh to {user}@{self.remote}: '
        try:
            self.client.connect(self.remote, username=user,
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
        # Get a pty so that stderr will be combined with stdout. Otherwise, we
        # only get stderr if there is any output on stderr.
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
        return result, exit_status


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
        DEBUG('self.paths={self.paths}')
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

    def get_value(self, target, key):
        # Return value from section [target]
        value = self._get_value(target, key)
        if value:
            return value

        # Maybe implement a [default] section in the future?
        return None

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
    def __init__(self, name, remote, config, command, lvsvolume,
                 mqueue, debug=False, timeout=5):
        self.name = name
        self.remote = remote
        self.config = config
        self.command = command
        self.lvsvolume = lvsvolume
        self.mqueue = mqueue
        self.debug = debug
        self.timeout = timeout

        self.user = self.config.get_value(remote, 'username')
        if self.user is None:
            self.user = 'root'
        elif isinstance(self.user, list):
            self.user = self.user[0]

        self.partitions = None  # for pylint
        self._clear_status()
        self.ssh = Ssh(self.remote, self.user, debug=self.debug,
                       timeout=self.timeout)

    def INFO(self, message):
        self.mqueue.put((self.name, message))

    def FATAL(self, message) -> typing.NoReturn:
        self.mqueue.put((self.name, message))
        sys.exit(1)

    def _dump(self, result):
        for line in result:
            self.INFO(line)

    def _get_partitions(self):
        if self.partitions is None:
            self.partitions, _ = self.ssh.execute('cat /proc/partitions')

    def _clear_status(self):
        self.uuid_devs = {}
        self.uuid_md = {}
        self.mds = set()
        self.encrypted = set()
        self.partitions = None
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
        self._get_partitions()
        DEBUG('determining device status')
        for partition in self.partitions:
            if partition.startswith('major') or partition == '':
                continue
            _, _, _, name = partition.split()
            dev = os.path.join("/dev/", name)

            # For the non-md devices, determine the UUID of the md of the
            # associated md device, if applicable.
            result, _ = self.ssh.execute(f'mdadm -Q --examine {dev}')
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
            result, _ = self.ssh.execute(f'mdadm -Q --detail {dev}')
            for line in result:
                if re.search(r'UUID : ', line):
                    uuid = re.sub('.* UUID : ', '', line).strip()
                    self.uuid_md[uuid] = name
                    self.mds.add(name)
                if uuid and re.search(r'Failed Devices :', line):
                    failed = re.sub('.* Devices : ', '', line).strip()
                    self.failed[uuid] = int(failed)

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
    def _human(size):
        if size == '':
            return ''
        size = int(size)
        units = ['b', 'KiB', 'MiB', 'GiB', 'TiB']
        unit = 0
        while size > 1024 and unit < len(units) - 1:
            size /= 1024
            unit += 1
        return f'{size:.2f}{units[unit]}'

    def status(self):
        self._get_status()
        # Report md devices
        for uuid, devs in self.uuid_devs.items():
            devs = ' '.join(sorted(devs))
            md = self.uuid_md.get(uuid, '')
            size, _ = self.sizes.get(uuid, ('', ''))
            size = self._human(size)
            level = self.level.get(uuid, '')
            failed = self.failed.get(uuid, 0)
            self.INFO(
                f'{md:5s} {uuid:35s} {size:10s} {level:6s} {failed} {devs}')

            if failed > 0:
                self.INFO(f'{uuid:41s} {failed} device(s) FAILED **********')

        # Report volume mappings
        for volume, deps in self.mapping.items():
            deps = ' '.join(sorted(deps))
            size, _ = self.sizes.get(volume, ('', ''))
            size = self._human(size)
            self.INFO(f'{volume:41s} {size:17s} {deps}')
        # Report mounts
        for volume, (mountpoint, fstype) in self.mounts.items():
            size, used = self.sizes.get(mountpoint, ('', ''))
            free = self._human(int(size) - int(used))
            size = self._human(size)
            self.INFO(
                f'{mountpoint:30s} {free:10s} {size:10s} {fstype:6s} {volume}')

    def _get_luks_key(self, uuid):
        # pylint: disable=broad-except
        luks_key = ''
        for key in ['key0', 'key1', 'key2', 'key3']:
            key_remote = self.config.get_value(self.remote, key)
            if key_remote is not None and len(key_remote) > 0:
                try:
                    secret = ursecret.UrSecret(key_remote[0],
                                               socket.gethostname(),
                                               debug=self.debug)
                    secret.locate_key()
                    luks_key += secret.get_secret(uuid)
                except Exception:
                    pass
        return luks_key

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
                    secret = ursecret.UrSecret(key_remote[0],
                                               socket.gethostname(),
                                               debug=self.debug)
                    partial = secrets.token_hex(64)
                    secret.locate_key()
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

    def run(self):
        if self.command == 'status':
            self.status()
        elif self.command == 'up':
            self.up()
        elif self.command == 'down':
            self.down()
        elif self.command == 'CREATE':
            self.create()
        else:
            FATAL(f'Illegal command: {self.command}')


class Pool():
    def __init__(self, remote_list, config, command, lvsvolume=None,
                 debug=False, max_workers=4, timeout=5):
        self.remote_list = remote_list
        self.config = config
        self.command = command
        self.lvsvolume = lvsvolume
        self.debug = debug
        self.max_workers = max_workers
        self.timeout = timeout

    @staticmethod
    def _worker(name, remote, config, command, lvsvolume, mqueue,
                debug=False, timeout=5):
        try:
            raid = Raid(name, remote, config, command, lvsvolume, mqueue,
                        debug=debug, timeout=timeout)
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
                    mqueue)
                jobs[name] = future

                future.add_done_callback(lambda future, name=name:
                                         self._done_callback(name, future))

            running = True
            while running:
                try:
                    name, message = mqueue.get(False)
                    INFO('%s: %s', name, message)
                except queue.Empty:
                    running = False
                    for name, future in jobs.items():
                        running |= future.running()
                    time.sleep(1)

            while not mqueue.empty():
                name, message = mqueue.get(False)
                INFO('%s: %s', name, message)


def main():
    parser = argparse.ArgumentParser(
        description='Configure, start, and stop remote data stores')
    parser.add_argument('target', type=str, nargs='?',
                        help='target host or comma separated list of hosts')
    parser.add_argument('command', type=str, nargs='?',
                        help='command (status|up|down|CREATE)')
    parser.add_argument('--lvsvolume', type=str,
                        help='name of lvs volume for CREATE, e.g., v0-data')
    parser.add_argument('--config', default=None,
                        help='configuration file')
    parser.add_argument('--dump', action='store_true', default=False,
                        help='dump config file and exit')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='verbose debugging output')
    args = parser.parse_args()

    logging.getLogger('paramiko').setLevel(logging.WARNING)
    if args.debug:
        Log.logger.setLevel(logging.DEBUG)
        logging.getLogger('paramiko').setLevel(logging.INFO)

    INFO(f'target={args.target}')
    INFO(f'command={args.command}')

    config = Config(args.config)
    if args.dump:
        INFO(f'config={config.dump()}')
        sys.exit(0)

    if args.target is None or args.command is None or args.command not in [
            'status', 'up', 'down', 'CREATE']:
        parser.print_help()
        sys.exit(1)

    if re.search(',', args.target):
        target_list = args.target.split(',')
    else:
        target_list = [args.target]

    INFO(f'target_list={target_list}')

    if args.command == 'CREATE' and (not args.lvsvolume or
                                     len(target_list) > 1):
        parser.print_help()
        sys.exit(1)

    pool = Pool(target_list, config, args.command, lvsvolume=args.lvsvolume,
                debug=args.debug)
    pool.run()


if __name__ == '__main__':
    main()
    sys.exit(0)
