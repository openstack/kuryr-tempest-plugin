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

import time

from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from kuryr_tempest_plugin.tests.scenario import base

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestPortPoolScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestPortPoolScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.port_pool_enabled:
            raise cls.skipException(
                "Port pool feature should be enabled to run this test.")

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

        # to test the reload of the pools, we will also test the restart of the
        # kuryr-controller
        kube_system_pods = self.get_pod_name_list(
            namespace=CONF.kuryr_kubernetes.kube_system_namespace)
        for kuryr_pod_name in kube_system_pods:
            if kuryr_pod_name.startswith('kuryr-controller'):
                self.delete_pod(
                    pod_name=kuryr_pod_name,
                    body={"kind": "DeleteOptions",
                          "apiVersion": "v1",
                          "gracePeriodSeconds": 0},
                    namespace=CONF.kuryr_kubernetes.kube_system_namespace)

                # make sure the kuryr pod was deleted
                self.wait_for_pod_status(
                    kuryr_pod_name,
                    namespace=CONF.kuryr_kubernetes.kube_system_namespace)

        # Check that new kuryr-controller is up and running
        kube_system_pods = self.get_pod_name_list(
            namespace=CONF.kuryr_kubernetes.kube_system_namespace)
        for kube_system_pod in kube_system_pods:
            if kube_system_pod.startswith('kuryr-controller'):
                self.wait_for_pod_status(
                    kube_system_pod,
                    namespace=CONF.kuryr_kubernetes.kube_system_namespace,
                    pod_status='Running',
                    retries=120)

                # Wait until kuryr-controller pools are reloaded, i.e.,
                # kuryr-controller is ready
                pod_readiness_retries = 30
                while not self.get_pod_readiness(
                        kube_system_pod,
                        namespace=CONF.kuryr_kubernetes.kube_system_namespace,
                        container_name='controller'):
                    time.sleep(1)
                    pod_readiness_retries -= 1
                    if pod_readiness_retries == 0:
                        raise lib_exc.TimeoutException()

        # create additional pod
        pod_name, pod = self.create_pod()
        self.addCleanup(self.delete_pod, pod_name, pod)

        # the port pool should stay the same
        updated3_port_list_num = len(
            self.os_admin.ports_client.list_ports()['ports'])
        self.assertEqual(updated_port_list_num, updated3_port_list_num)
