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

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc


from kuryr_tempest_plugin.tests.scenario import base

CONF = config.CONF


class TestKuryrRestartScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestKuryrRestartScenario, cls).skip_checks()
        if (not CONF.kuryr_kubernetes.containerized or
                not CONF.kuryr_kubernetes.run_tests_serial):
            raise cls.skipException(
                "CNI and controller should be containerized and this test "
                "should run on gate, configured to run sequentially.")

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdcfb1a1a7')
    def test_kuryr_pod_delete(self):
        # find kuryr CNI and controller pods, delete them one by one and create
        #  a regular pod just after removal
        kube_system_pods = self.get_pod_name_list(
            namespace=CONF.kuryr_kubernetes.kube_system_namespace)
        for kuryr_pod_name in kube_system_pods:
            if kuryr_pod_name.startswith('kuryr'):
                self.delete_pod(
                    pod_name=kuryr_pod_name,
                    body={"kind": "DeleteOptions",
                          "apiVersion": "v1",
                          "gracePeriodSeconds": 0},
                    namespace=CONF.kuryr_kubernetes.kube_system_namespace)

                # make sure the kuryr pod was deleted
                pod_delete_retries = 30
                while self.get_pod_status(
                        kuryr_pod_name,
                        namespace=CONF.kuryr_kubernetes.kube_system_namespace):
                    time.sleep(1)
                    pod_delete_retries -= 1
                    if pod_delete_retries == 0:
                        raise lib_exc.TimeoutException()

                # Create a new pod while kuryr CNI or kuryr controller Pods are
                # not in the running state.
                # Check once for controller kuryr pod and once for CNI pod
                pod_name, pod = self.create_pod()
                self.addCleanup(self.delete_pod, pod_name)
                pod_fip = self.assign_fip_to_pod(pod_name)
                self.assertIsNotNone(pod_fip['floatingip'][
                    'floating_ip_address'])
                self.assertTrue(self.ping_ip_address(pod_fip[
                    'floatingip']['floating_ip_address']))

        # Check that both kuryr-pods are up and running
        # The newly created pods are running because create_pod is written
        # that way. Will be refactored in another patch
        for new_kuryr_pod in self.get_pod_name_list(
                namespace=CONF.kuryr_kubernetes.kube_system_namespace):
            self.assertEqual("Running", self.get_pod_status(
                new_kuryr_pod,
                namespace=CONF.kuryr_kubernetes.kube_system_namespace))
