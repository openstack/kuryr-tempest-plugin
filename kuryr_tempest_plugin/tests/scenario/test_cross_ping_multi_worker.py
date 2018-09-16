# Copyright 2018 Red Hat, Inc.
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

from kuryr_tempest_plugin.tests.scenario import base
from kuryr_tempest_plugin.tests.scenario import consts

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestCrossPingScenarioMultiWorker(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestCrossPingScenarioMultiWorker, cls).skip_checks()
        if not CONF.kuryr_kubernetes.multi_worker_setup:
            raise cls.skipException("Multi node workers are not available")

    def _test_cross_ping_multi_worker(self, same_node=True):
        if same_node:
            pod_name_list = self.create_two_pods_affinity_setup(
                labels={'type': 'demo'},
                affinity={'podAffinity': consts.POD_AFFINITY})
            self.assertEqual(self.get_pod_node_name(pod_name_list[0]),
                             self.get_pod_node_name(pod_name_list[1]))
        else:
            pod_name_list = self.create_two_pods_affinity_setup(
                labels={'type': 'demo'},
                affinity={'podAntiAffinity': consts.POD_AFFINITY})
            self.assertNotEqual(self.get_pod_node_name(pod_name_list[0]),
                                self.get_pod_node_name(pod_name_list[1]))
        pod_ip = self.get_pod_ip(pod_name_list[1])
        cmd = [
            "/bin/sh", "-c", "ping -c 4 {dst_ip}>/dev/null ; echo $?".format(
                dst_ip=pod_ip)]
        self.assertEqual(self.exec_command_in_pod(pod_name_list[0], cmd), '0')

    @decorators.idempotent_id('7d036b6d-b5cf-47e9-a0c0-7696240a1c5e')
    def test_pod_pod_ping_different_host(self):
        self._test_cross_ping_multi_worker(same_node=False)

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fddfb1a2a9')
    def test_pod_pod_ping_same_node(self):
        self._test_cross_ping_multi_worker(same_node=True)
