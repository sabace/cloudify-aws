__author__ = 'Ganesh'

'''
Created on 24-Feb-2014
Cloudify Amazon Provider Interface
@author: Ganesh
'''

########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############

# Standard
import os
import errno
import shutil
import inspect
import itertools
import time
import yaml
import json
import socket
import paramiko
import tempfile
import sys
from os.path import expanduser
from copy import deepcopy
from scp import SCPClient
from fabric.api import run, env
from fabric.context_managers import settings, hide
import logging
import logging.config
import config

# Amazon
from boto.ec2 import connect_to_region
from boto.ec2.instanceinfo import InstanceInfo
from boto.vpc import VPCConnection

EP_FLAG = 'externally_provisioned'

EXTERNAL_PORTS = (22, 8100)  # SSH, REST service
INTERNAL_PORTS = (5555, 5672, 53229)  # Riemann, RabbitMQ, FileServer

SSH_CONNECT_RETRIES = 15
SSH_CONNECT_SLEEP = 10

SHELL_PIPE_TO_LOGGER = ' |& logger -i -t cosmo-bootstrap -p local0.info'

CONFIG_FILE_NAME = 'cloudify-config.yaml'
DEFAULTS_CONFIG_FILE_NAME = 'cloudify-config.defaults.yaml'

verbose_output = False


#initialize logger
try:
    d = os.path.dirname(config.LOGGER['handlers']['file']['filename'])
    if not os.path.exists(d):
        os.makedirs(d)
    logging.config.dictConfig(config.LOGGER)
    lgr = logging.getLogger('main')
    lgr.setLevel(logging.INFO)
except ValueError:
    sys.exit('could not initialize logger.'
             ' verify your logger config'
             ' and permissions to write to {0}'
             .format(config.LOGGER['handlers']['file']['filename']))

# http://stackoverflow.com/questions/8144545/turning-off-logging-in-paramiko
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(
    logging.ERROR)


def init(target_directory, reset_config, is_verbose_output=False):
    _set_global_verbosity_level(is_verbose_output)

    if not reset_config and os.path.exists(
            os.path.join(target_directory, CONFIG_FILE_NAME)):
        return False

    provider_dir = os.path.dirname(os.path.realpath(__file__))
    files_path = os.path.join(provider_dir, CONFIG_FILE_NAME)

    lgr.debug('copying provider files from {0} to {1}'
              .format(files_path, target_directory))
    shutil.copy(files_path, target_directory)
    return True


def bootstrap(config_path=None, is_verbose_output=False,
              bootstrap_using_script=True):
    _set_global_verbosity_level(is_verbose_output)
    provider_config = _read_config(config_path)
    connector = AwsConnector(provider_config)
    lgr.debug(connector.aws_status())
    network_creator = AwsNetworkCreator(connector)
    subnet_creator = AwsSubnetCreator(connector)
    router_creator = AwsRouterCreator(connector)
    floating_ip_creator = AwsFloatingIpCreator(connector)

    keypair_creator = AwsKeypairCreator(connector)
    server_creator = AwsServerCreator(connector)
    sg_creator = AwsSecurityGroupCreator(connector)

    bootstrapper = CosmoOnAwsBootstrapper(
        provider_config, network_creator, subnet_creator, router_creator,
        sg_creator, floating_ip_creator, keypair_creator, server_creator)
    mgmt_ip = bootstrapper.do(bootstrap_using_script)
    return mgmt_ip


def teardown(management_ip, is_verbose_output=False):
    _set_global_verbosity_level(is_verbose_output)

    lgr.debug('NOT YET IMPLEMENTED')
    raise RuntimeError('NOT YET IMPLEMENTED')


def _set_global_verbosity_level(is_verbose_output=False):
    # we need both lgr.setLevel and the verbose_output parameter
    # since not all output is generated at the logger level.
    # verbose_output can help us control that.
    global verbose_output
    verbose_output = is_verbose_output
    if verbose_output:
        lgr.setLevel(logging.DEBUG)


def _read_config(config_file_path):
    if not config_file_path:
        config_file_path = CONFIG_FILE_NAME
    defaults_config_file_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        DEFAULTS_CONFIG_FILE_NAME)

    if not os.path.exists(config_file_path) or not os.path.exists(
            defaults_config_file_path):
        if not os.path.exists(defaults_config_file_path):
            # noinspection PyPep8
            raise ValueError('Missing the defaults configuration file; '
                             'expected to find it at {0}'.format(
                defaults_config_file_path))
        raise ValueError('Missing the configuration file; expected to find '
                         'it at {0}'.format(config_file_path))

    lgr.debug('reading provider config files')
    with open(config_file_path, 'r') as config_file, \
            open(defaults_config_file_path, 'r') as defaults_config_file:

        lgr.debug('safe loading user config')
        user_config = yaml.safe_load(config_file.read())

        lgr.debug('safe loading default config')
        defaults_config = yaml.safe_load(defaults_config_file.read())

    lgr.debug('merging configs')
    merged_config = _deep_merge_dictionaries(user_config, defaults_config) \
        if user_config else defaults_config
    lgr.debug(merged_config)
    return merged_config


def _deep_merge_dictionaries(overriding_dict, overridden_dict):
    merged_dict = deepcopy(overridden_dict)
    for k, v in overriding_dict.iteritems():
        if k in merged_dict and isinstance(v, dict):
            if isinstance(merged_dict[k], dict):
                merged_dict[k] = _deep_merge_dictionaries(v, merged_dict[k])
            else:
                raise RuntimeError('type conflict at key {0}'.format(k))
        else:
            merged_dict[k] = deepcopy(v)
    return merged_dict


def _mkdir_p(path):
    try:
        lgr.debug('creating dir {0}'
                  .format(path))
        os.makedirs(path)
    except OSError, exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            return
        raise


class CosmoOnAwsBootstrapper(object):
    """ Bootstraps Cosmo on Aws """

    def __init__(self, provider_config, network_creator, subnet_creator,
                 router_creator, sg_creator, floating_ip_creator,
                 keypair_creator, server_creator):
        self.config = provider_config
        self.network_creator = network_creator
        self.subnet_creator = subnet_creator
        self.router_creator = router_creator
        self.sg_creator = sg_creator
        self.floating_ip_creator = floating_ip_creator
        self.keypair_creator = keypair_creator
        self.server_creator = server_creator

        global verbose_output
        self.verbose_output = verbose_output

    def do(self, bootstrap_using_script):
        mgmt_ip = self._create_topology()
        self._bootstrap_manager(mgmt_ip, bootstrap_using_script)
        return mgmt_ip

    def _create_topology(self):
        compute_config = self.config['compute']

        insconf = compute_config['management_server']['instance']

        # Security group for Cosmo created instances
        asgconf = self.config['networking']['agents_security_group']
        lgr.debug(asgconf)
        asg_id = self.sg_creator.create_or_ensure_exists(
            asgconf,
            asgconf['name'],
            'Cosmo created machines',
            [])

        # Security group for Cosmo manager, allows created
        # instances -> manager communication
        msgconf = self.config['networking']['management_security_group']
        sg_rules = \
            [{'port': p, 'group_id': asg_id} for p in INTERNAL_PORTS] + \
            [{'port': p, 'cidr': msgconf['cidr']} for p in EXTERNAL_PORTS]
        msg_id = self.sg_creator.create_or_ensure_exists(
            msgconf,
            msgconf['name'],
            'Cosmo Manager',
            sg_rules)

        # Keypairs setup
        mgr_kpconf = compute_config['management_server']['management_keypair']
        self.keypair_creator.create_or_ensure_exists(
            mgr_kpconf,
            mgr_kpconf['name'],
            private_key_target_path=
            mgr_kpconf['auto_generated']['private_key_target_path'] if
            'auto_generated' in mgr_kpconf else None,
            public_key_filepath=
            mgr_kpconf['provided']['public_key_filepath'] if
            'provided' in mgr_kpconf else None
        )
        agents_kpconf = compute_config['agent_servers']['agents_keypair']
        self.keypair_creator.create_or_ensure_exists(
            agents_kpconf,
            agents_kpconf['name'],
            private_key_target_path=agents_kpconf['auto_generated']
            ['private_key_target_path'] if 'auto_generated' in
                                           agents_kpconf else None,
            public_key_filepath=
            agents_kpconf['provided']['public_key_filepath'] if
            'provided' in agents_kpconf else None
        )

        server_id = self.server_creator.create_or_ensure_exists(
            insconf,
            insconf['name'],
            {k: v for k, v in insconf.iteritems() if k != EP_FLAG},
            mgr_kpconf['name'],
            msgconf['name'],
        )

        return server_id

    def _attach_floating_ip(self, mgmt_server_conf, enet_id, server_id):
        pass

    def _get_private_key_path_from_keypair_config(self, keypair_config):
        path = keypair_config['provided']['private_key_filepath'] if \
            'provided' in keypair_config else \
            keypair_config['auto_generated']['private_key_target_path']
        return expanduser(path)

    def _run_with_retries(self, command, retries=3, sleeper=3):
        for execution in range(retries):
            lgr.debug('running command: {0}'
                      .format(command))
            if not self.verbose_output:
                with hide('running', 'stdout'):
                    r = run(command)
            else:
                r = run(command)
            if r.succeeded:
                lgr.debug('successfully ran command: {0}'
                          .format(command))
                return
            else:
                lgr.warning('retrying command: {0}'
                            .format(command))
                time.sleep(sleeper)
        lgr.error('failed to run: {0}, {1}'
                  .format(command), r.stdout)
        return

    def _download_package(self, url, path):
        self._run_with_retries('sudo wget %s -P %s' % (path, url))

    def _unpack(self, path):
        self._run_with_retries('sudo dpkg -i %s/*.deb' % path)

    def _run(self, command):
        self._run_with_retries(command)

    def _bootstrap_manager(self, mgmt_ip, bootstrap_using_script):
        lgr.info('initializing manager on the machine at {0}'
                 .format(mgmt_ip))
        compute_config = self.config['compute']
        cosmo_config = self.config['cloudify']
        management_server_config = compute_config['management_server']
        mgr_kpconf = compute_config['management_server']['management_keypair']

        lgr.debug('creating ssh channel to machine...')
        ssh = self._create_ssh_channel_with_mgmt(
            mgmt_ip,
            self._get_private_key_path_from_keypair_config(
                management_server_config['management_keypair']),
            management_server_config['user_on_management'])

        env.user = management_server_config['user_on_management']
        env.warn_only = 0
        env.abort_on_prompts = False
        env.connection_attempts = 5
        env.keepalive = 0
        env.linewise = False
        env.pool_size = 0
        env.skip_bad_hosts = False
        env.timeout = 10
        env.forward_agent = True
        env.status = False
        env.key_filename = [mgr_kpconf['auto_generated']
                            ['private_key_target_path']]

        if not bootstrap_using_script:

            self._copy_files_to_manager(
                ssh,
                management_server_config['userhome_on_management'],
                self.config['Amazon Credentials'],
                self._get_private_key_path_from_keypair_config(
                    compute_config['agent_servers']['agents_keypair']))

            with settings(host_string=mgmt_ip), hide('running'):

                lgr.info('downloading cloudify components package...')
                self._download_package(
                    cosmo_config['cloudify_packages_path'],
                    cosmo_config['cloudify_components_package_url'])

                lgr.info('downloading cloudify package...')
                self._download_package(
                    cosmo_config['cloudify_packages_path'],
                    cosmo_config['cloudify_package_url'])

                lgr.info('unpacking cloudify packages...')
                self._unpack(
                    cosmo_config['cloudify_packages_path'])

                lgr.debug('verifying verbosity for installation process')
                v = self.verbose_output
                self.verbose_output = True

                lgr.info('installing cloudify on {0}...'.format(mgmt_ip))
                self._run('sudo %s/cloudify3-components-bootstrap.sh' %
                          cosmo_config['cloudify_components_package_path'])

                self._run('sudo %s/cloudify3-bootstrap.sh' %
                          cosmo_config['cloudify_package_path'])

                lgr.debug('setting verbosity to previous state')
                self.verbose_output = v
        else:
            try:
                self._copy_files_to_manager(
                    ssh,
                    management_server_config['userhome_on_management'],
                    self.config['Amazon Credentials'],
                    self._get_private_key_path_from_keypair_config(
                        compute_config['agent_servers']['agents_keypair']))

                lgr.debug('Installing required packages'
                          ' on manager')
                self._exec_command_on_manager(ssh, 'echo "127.0.0.1 '
                                                   '$(cat /etc/hostname)" | '
                                                   'sudo tee -a /etc/hosts')
                self._exec_command_on_manager(ssh, 'sudo apt-get -y -q update'
                                                   + SHELL_PIPE_TO_LOGGER)
                self._exec_install_command_on_manager(ssh,
                                                      'apt-get install -y -q '
                                                      'python-dev git rsync '
                                                      'openjdk-7-jdk maven '
                                                      'python-pip'
                                                      + SHELL_PIPE_TO_LOGGER)
                self._exec_install_command_on_manager(ssh, 'pip install -q '
                                                           'retrying '
                                                           'timeout-decorator')

                # use open sdk java 7
                self._exec_command_on_manager(
                    ssh,
                    'sudo update-alternatives --set java '
                    '/usr/lib/jvm/java-7-openjdk-amd64/jre/bin/java')

                # configure and clone cosmo-manager from github
                branch = cosmo_config['cloudify_branch']
                workingdir = '{0}/cosmo-work'.format(
                    management_server_config['userhome_on_management'])
                version = cosmo_config['cloudify_branch']
                configdir = '{0}/cosmo-manager/vagrant'.format(workingdir)

                lgr.debug('cloning cosmo on manager')
                self._exec_command_on_manager(ssh, 'mkdir -p {0}'
                                              .format(workingdir))
                self._exec_command_on_manager(ssh,
                                              'git clone https://github.com/'
                                              'CloudifySource/cosmo-manager'
                                              '.git {0}/cosmo-manager'
                                              ' --depth 1'
                                              .format(workingdir))
                self._exec_command_on_manager(ssh, '( cd {0}/cosmo-manager ; '
                                                   'git checkout {1} )'
                                              .format(workingdir, branch))

                lgr.debug('running the manager bootstrap script '
                          'remotely')
                run_script_command = 'DEBIAN_FRONTEND=noninteractive ' \
                                     'python2.7 {0}/cosmo-manager/vagrant/' \
                                     'bootstrap_lxc_manager.py ' \
                                     '--working_dir={0} --cosmo_version={1} ' \
                                     '--config_dir={2} ' \
                                     '--install_openstack_provisioner ' \
                                     '--install_logstash' \
                    .format(workingdir, version, configdir)
                run_script_command += ' {0}'.format(SHELL_PIPE_TO_LOGGER)
                self._exec_command_on_manager(ssh, run_script_command)

                lgr.debug('rebuilding cosmo on manager')
            finally:
                ssh.close()

    def _create_ssh_channel_with_mgmt(self, mgmt_ip, management_key_path,
                                      user_on_management):
        ssh = paramiko.SSHClient()
        # TODO: support fingerprint in config json
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        #trying to ssh connect to management server. Using retries since it
        #might take some time to find routes to host
        for retry in range(0, SSH_CONNECT_RETRIES):
            try:
                ssh.connect(mgmt_ip, username=user_on_management,
                            key_filename=management_key_path,
                            look_for_keys=False)
                return ssh
            except socket.error:
                lgr.debug(
                    "SSH connection to {0} failed. Waiting {1} seconds "
                    "before retrying".format(mgmt_ip, SSH_CONNECT_SLEEP))
                time.sleep(SSH_CONNECT_SLEEP)
        raise RuntimeError('Failed to ssh connect to management server')

    def _copy_files_to_manager(self, ssh, userhome_on_management,
                               aws_auth_config, agents_key_path):
        lgr.info('uploading Aws Auth files to manager')
        scp = SCPClient(ssh.get_transport())

        tempdir = tempfile.mkdtemp()
        try:
            scp.put(agents_key_path, userhome_on_management + '/.ssh',
                    preserve_times=True)
            aws_auth_file_path = self._make_auth_file(tempdir,
                                                      aws_auth_config)
            scp.put(aws_auth_file_path, userhome_on_management,
                    preserve_times=True)

        finally:
            shutil.rmtree(tempdir)

    def _make_auth_file(self, tempdir, aws_auth_config):
        aws_auth_file_path = os.path.join(tempdir, 'aws_auth_config.json')
        with open(aws_auth_file_path, 'w') as f:
            json.dump(aws_auth_config, f)
        return aws_auth_file_path

    def _exec_install_command_on_manager(self, ssh, install_command):
        command = 'DEBIAN_FRONTEND=noninteractive sudo -E {0}'.format(
            install_command)
        return self._exec_command_on_manager(ssh, command)

    def _exec_command_on_manager(self, ssh, command):
        lgr.info('EXEC START: {0}'.format(command))
        chan = ssh.get_transport().open_session()
        while chan.closed:
            time.sleep(4)
            lgr.debug("waiting Chan session to open")
            chan = ssh.get_transport().open_session()
        chan.exec_command(command)
        stdin = chan.makefile('wb', -1)
        stdout = chan.makefile('rb', -1)
        stderr = chan.makefile_stderr('rb', -1)

        try:
            exit_code = chan.recv_exit_status()
            if exit_code != 0:
                errors = stderr.readlines()
                raise RuntimeError('Error occurred when trying to run a '
                                   'command on the management machine. '
                                   'command was: {0} ; Error(s): {1}'
                                   .format(command, errors))

            response_lines = stdout.readlines()
            lgr.info('EXEC END: {0}'.format(command))
            return response_lines
        finally:
            stdin.close()
            stdout.close()
            stderr.close()
            chan.close()


class AwsLogicError(RuntimeError):
    pass


class CreateOrEnsureExists(object):
    WHAT = None

    def create_or_ensure_exists(self, provider_config, name, *args, **kw):
        # config hash is only used for 'externally_provisioned' attribute
        if EP_FLAG in provider_config and provider_config[EP_FLAG]:
            method = 'ensure_exists'
        else:
            method = 'check_and_create'
        return getattr(self, method)(name, *args, **kw)

    def check_and_create(self, name, *args, **kw):
        lgr.debug("Will create {0} '{1}'".format(
            self.__class__.WHAT, name))
        if self.list_objects_with_name(name):
            raise AwsLogicError("{0} '{1}' already exists".format(
                self.__class__.WHAT, name))
        return self.create(name, *args, **kw)

    def ensure_exists(self, name, *args, **kw):
        lgr.debug("Will use existing {0} '{1}'"
                  .format(self.__class__.WHAT, name))
        ret = self.find_by_name(name)
        if not ret:
            raise AwsLogicError("{0} '{1}' was not found".format(
                self.__class__.WHAT, name))
        return ret['id']

    def find_by_name(self, name):
        matches = self.list_objects_with_name(name)

        if len(matches) == 0:
            return None
        if len(matches) == 1:
            return matches[0]
        raise AwsLogicError("Lookup of {0} named '{1}' failed. There "
                            "are {2} matches."
                            .format(self.__class__.WHAT, name,
                                    len(matches)))

    def _fail_on_missing_required_parameters(self, obj, required_parameters,
                                             hint_where):
        for k in required_parameters:
            if k not in obj:
                raise AwsLogicError("Required parameter '{0}' is "
                                    "missing (under {3}'s properties."
                                    "{1}). "
                                    "Required parameters are: {2}"
                                    .format(k, hint_where,
                                            required_parameters,
                                            self.__class__.WHAT))


class CreateOrEnsureExistsAws(CreateOrEnsureExists):
    def __init__(self, connector):
        CreateOrEnsureExists.__init__(self)
        self.aws_client = connector.aws_connection()
        #self.vpc_client = connector.get_vpc_client()


class CreateOrEnsureExistsVPC(CreateOrEnsureExists):
    def __init__(self, connector):
        CreateOrEnsureExists.__init__(self)

    #     self.vpc_client = connector.get_vpc_client()
    #     print "vpc client", self.vpc_client
    pass


class AwsNetworkCreator(CreateOrEnsureExistsVPC):
    WHAT = 'network'
    pass
    # def list_objects_with_name(self, *vpn_id):
    #     #return self.vpc_client.get_all_vpn_connections(vpn_connection_ids=vpn_id), "list objects"
    #     #on hold vpc #
    #     pass
    #
    # def create(self, vpn_id):
    #     # n = vpn_id
    #     # ret = self.vpc_client.create_vpc(cidr_block=n)
    #     # print ret, "vpn "
    #     #return ret['network']['id']
    #     pass


class AwsSubnetCreator(CreateOrEnsureExistsVPC):
    WHAT = 'subnet'
    pass
    # def list_objects_with_name(self, *subnet_id):
    #     #return self.vpc_client.get_all_subnets(subnet_ids=subnet_id, filters=None)
    #     pass
    #
    # def create(self, cidr, vpc_id, zone=None):
    #     # ret = self.vpc_client.create_subnet(self, vpc_id=vpc_id,
    #     #                                     cidr_block=cidr,
    #     #                                     availability_zone=zone)
    #     # print ret, "subnet"
    #     # return ret['subnet']['id']
    #     pass


class AwsFloatingIpCreator():
    def __init__(self, connector):
        pass
        #self.vpc_client = connector.get_vpc_client()
        #
        # def allocate_ip(self, external_network_id, inst_id):
        #     ret = self.vpc_client.associate_address(instance_id=inst_id,
        #                                             public_ip=None,
        #                                             allocation_id=external_network_id)
        #     return ret


class AwsRouterCreator(CreateOrEnsureExistsVPC):
    WHAT = 'router'
    pass
    # def list_objects_with_name(self, *name):
    #     return self.vpc_client.get_all_route_tables(route_table_ids=name, filters=None)
    #
    # def create(self, vpc_id):
    #     ret = self.vpc_client.create_route_table(self, vpc_id)
    #     return ret  #router_id


class AwsSecurityGroupCreator(CreateOrEnsureExistsAws):
    WHAT = 'security group'

    def list_objects_with_name(self, name):
        sgs = self.aws_client.get_all_security_groups(groupnames=None,
                                                      group_ids=None,
                                                      filters=None)
        lgr.debug(sgs)
        return [{'id': sg.id} for sg in sgs if sg.name == name]

    def create(self, name, description, rules):
        sg = self.aws_client.create_security_group(name, description,
                                                   vpc_id=None)
        for rule in rules:
            self.aws_client.authorize_security_group(
                ip_protocol="tcp",
                from_port=rule['port'],
                to_port=rule['port'],
                cidr_ip=rule.get('cidr'),
                group_id=sg.id
            )
        return sg.id


class AwsKeypairCreator(CreateOrEnsureExistsAws):
    WHAT = 'keypair'

    def list_objects_with_name(self, name):
        keypairs = self.aws_client.get_key_pair(name) or []
        return keypairs

    def create(self, key_name, private_key_target_path=None,
               public_key_filepath=None, *args, **kwargs):
        if not private_key_target_path and not public_key_filepath:
            raise RuntimeError("Must provide either private key target path "
                               "or public key filepath to create keypair")

        if public_key_filepath:
            with open(public_key_filepath, 'r') as f:
                self.aws_client.create_key_pair(f.read(), key_name)
        else:
            key = self.aws_client.create_key_pair(key_name)
            pk_target_path = expanduser(private_key_target_path)
            _mkdir_p(os.path.dirname(pk_target_path))
            with open(pk_target_path, 'wb') as f:
                f.write(key.material)
                os.system('chmod 600 {0}'.format(pk_target_path))


class AwsServerCreator(CreateOrEnsureExistsAws):
    WHAT = 'server'

    def list_objects_with_name(self, name):
        servers = self.aws_client.get_all_instances()
        return [{"image_id": i.id, "state": i.state, "name": i.tags["Name"]}
                for r in servers for i in r.instances if i.tags if i.tags["Name"] == name]

    def create(self, name, server_config, management_server_keypair_name,
               sgm_id, *args, **kwargs):
        """
        Creates a server.
        """

        self._fail_on_missing_required_parameters(
            server_config,
            ('name', 'instance_type', 'image_id'),
            'compute.management_server.instance')

        # First parameter is 'self', skipping
        params_names = inspect.getargspec(
            self.aws_client.run_instances).args[2:]
        params_default_values = inspect.getargspec(
            self.aws_client.run_instances).defaults
        params = dict(itertools.izip(params_names, params_default_values))

        server_name = server_config['name']
        params["image_id"] = server_config["image_id"]

        del server_config['name']

        # Fail on unsupported parameters
        for k in server_config:
            if k not in params:
                raise ValueError("Parameter with name '{0}' must not be passed"
                                 " to Amazon provisioner (under "
                                 "compute.management_server.instance)"
                                 .format(k))

        for k in params:
            if k in server_config:
                params[k] = server_config[k]

        if self.find_by_name(server_name):
            raise RuntimeError("Can not provision the server with name '{0}'"
                               " because server with such name "
                               "already exists"
                               .format(server_name))

        lgr.debug("Asking Ec2 create server. Parameters: {0}"
                  .format(str(params)))

        configured_sgs = []
        if params['security_groups'] is not None:
            configured_sgs = params['security_groups']
        params['security_groups'] = [sgm_id] + configured_sgs

        params['key_name'] = management_server_keypair_name

        server = self.aws_client.run_instances(**params)

        server = self._wait_for_server_to_become_active(server, server_name)

        ##Assign name to server
        self.aws_client.create_tags([server.id], {"Name": server_name})

        return server.ip_address

    def add_floating_ip(self, server_id, ip):

        # Extra: detach floating ip from existng server
        while True:
            ls = self.aws_client.get_all_addresses(allocation_ids=ip)

            if len(ls) == 0:
                raise AwsLogicError(
                    "Floating IP {0} does not exist so it can "
                    "not be attached to server {1}".format(ip, server_id))
            if len(ls) > 1:
                raise AwsLogicError(
                    "Floating IP {0} is attached to "
                    "{1} instances".format(ip, len(ls)))

            if not ls[0].instance_id:
                lgr.debug(
                    "Floating IP {0} is not attached to any instance. "
                    "Continuing.".format(ip))
                break

            lgr.debug(
                "Floating IP {0} is attached "
                "to instance {1}. Detaching.".format(ip, ls[0].instance_id))
            self.aws_client.release_address(allocation_id=ip)
            #self.aws_client.remove_floating_ip(ls[0].instance_id, ip)
            time.sleep(1)

        server = self.aws_client.get_all_instances(instance_ids=server_id)
        server.associate_address(instance_id=server_id, public_ip=ip,
                                 allocation_id=None, )

    def get_server_ips_in_network(self, server_id, network_name):
        server = self.aws_client.get_all_instances(instance_ids=server_id)
        if network_name not in server.networks:
            raise AwsLogicError(
                "Server {0} ({1}) does not have address in"
                " network {2}".format(server.name, server_id, network_name))
        return server.networks[network_name]

    def _wait_for_server_to_become_active(self, server, server_name):
        timeout = 100
        while server.instances[0].state != "running":
            timeout -= 5
            if timeout <= 0:
                raise RuntimeError('Server failed to start in time')
            time.sleep(5)
            server = self.aws_client.get_all_instances(instance_ids=str(server.instances[0].id))[0]

        return server.instances[0]


class AwsConnector(object):
    def __init__(self, provider_config):
        try:
            self.config = provider_config["Amazon Credentials"]
        except KeyError:
            raise AwsLogicError("Required Values Amazon Credentials not there")

        if self.config:
            self.region = self.config["region"]
            self.access_key = self.config["accesskey"]
            self.secret_key = self.config["secretkey"]
            self.image_id = self.config["ami_id"]
            lgr.debug(self.image_id)
            self.aws_conn = connect_to_region(self.region,
                                              aws_access_key_id=self.access_key,
                                              aws_secret_access_key=self.secret_key)
            self.vpc_conn = VPCConnection(aws_access_key_id=self.access_key,
                                          aws_secret_access_key=self.secret_key)
        else:
            pass

    def aws_connection(self):
        return self.aws_conn

    def run_aws(self):
        pass
        # self.aws_conn.run_instances(self, image_id, min_count=1, max_count=1,
        #               key_name=None, security_groups=None,
        #               user_data=None, addressing_type=None,
        #               instance_type='m1.small', placement=None,
        #               kernel_id=None, ramdisk_id=None,
        #               monitoring_enabled=False, subnet_id=None,
        #               block_device_map=None,
        #               disable_api_termination=False,
        #               instance_initiated_shutdown_behavior=None,
        #               private_ip_address=None,
        #               placement_group=None, client_token=None,
        #               security_group_ids=None):
        #return self.aws_conn.run_instances(self.image_id)

    def aws_status(self):
        return InstanceInfo(connection=self.aws_conn, id=self.run_aws())

    def get_vpc_client(self):
        return self.vpc_conn

        # def create_vpc_client(self):
        #     self.aws_conn.
        #     return self.aws_conn.create_network_interface(subnet_id=subnet_id,
        #                                            private_ip_address=private_ip_address,
        #                                            description=description,
        #                                            groups=groups)

