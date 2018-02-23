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
import testtools

from kuryr_tempest_plugin.tests.scenario import base

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestPortPoolScenario(base.BaseKuryrScenarioTest):

    @testtools.skipUnless(
        CONF.kuryr_kubernetes.port_pool_enabled,
        "Port pool feature should be enabled to run this test")
    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fddfb1a3aa')
    def test_port_pool(self):
        # check the original length of list of ports
        port_list_num = len(self.os_admin.ports_client.list_ports()['ports'])

        # create a pod to test the port pool increase
        pod_name, pod = self.create_pod()
        self.addCleanup(self.delete_pod, pod_name, pod)

        # port number should increase by ports_pool_batch value
        updated_port_list_num = len(
            self.os_admin.ports_client.list_ports()['ports'])

        self.assertEqual(
            updated_port_list_num-CONF.vif_pool.ports_pool_batch,
            port_list_num)

        # create additional pod
        pod_name, pod = self.create_pod()
        self.addCleanup(self.delete_pod, pod_name, pod)

        # the port pool should stay the same
        updated2_port_list_num = len(
            self.os_admin.ports_client.list_ports()['ports'])
        self.assertEqual(updated_port_list_num, updated2_port_list_num)
