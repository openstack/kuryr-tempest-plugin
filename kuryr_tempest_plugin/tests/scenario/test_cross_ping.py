# Copyright 2017 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions

from kuryr_tempest_plugin.tests.scenario import base

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestCrossPingScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestCrossPingScenario, cls).skip_checks()
        if not CONF.network_feature_enabled.floating_ips:
            raise cls.skipException("Floating ips are not available")

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fddfb1a1a8')
    def test_vm_pod_ping(self):

        pod_name, pod = self.create_pod()
        self.addCleanup(self.delete_pod, pod_name, pod)
        pod_fip = self.assign_fip_to_pod(pod_name)
        ssh_client, fip = self.create_vm_for_connectivity_test()

        # check connectivity from VM to Pod
        cmd = ("ping -c4 -w4 %s &> /dev/null; echo $?" %
               pod_fip['floatingip']['floating_ip_address'])

        try:
            result = ssh_client.exec_command(cmd)
            if result:
                msg = ('Failed while trying to ping. Could not ping '
                       'from host "%s" to "%s".' % (
                           fip['floating_ip_address'],
                           pod_fip['floatingip']['floating_ip_address']))
                LOG.error(msg)
            self.assertEqual('0', result.rstrip('\n'))
        except exceptions.SSHExecCommandFailed:
            LOG.error("Couldn't ping server")

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fddfb1a1a8')
    def test_pod_vm_ping(self):
        _, fip = self.create_vm_for_connectivity_test()
        pod_name, pod = self.create_pod()
        self.addCleanup(self.delete_pod, pod_name, pod)

        # check connectivity from Pod to VM
        cmd = [
            "/bin/sh", "-c", "ping -c 4 {dst_ip}>/dev/null ; echo $?".format(
                dst_ip=fip['floating_ip_address'])]
        self.assertEqual(self.exec_command_in_pod(pod_name, cmd), '0')

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fddfb1a2a9')
    def test_pod_pod_ping(self):
        pod_name_list = []
        for i in range(2):
            pod_name, pod = self.create_pod()
            self.addCleanup(self.delete_pod, pod_name, pod)
            pod_name_list.append(pod_name)

        pod_ip = self.get_pod_ip(pod_name_list[1])
        cmd = [
            "/bin/sh", "-c", "ping -c 4 {dst_ip}>/dev/null ; echo $?".format(
                dst_ip=pod_ip)]
        self.assertEqual(self.exec_command_in_pod(pod_name_list[0], cmd), '0')
