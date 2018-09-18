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


from tempest import config
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base

CONF = config.CONF


class TestKuryrDaemon(base.BaseKuryrScenarioTest):
    @classmethod
    def skip_checks(cls):
        super(TestKuryrDaemon, cls).skip_checks()
        if (not CONF.kuryr_kubernetes.containerized) or (
           not CONF.kuryr_kubernetes.kuryr_daemon_enabled):
                raise cls.skipException("Kuryr cni should be containerized "
                                        "and Kuryr Daemon should be enabled "
                                        "to run this test.")

    @decorators.idempotent_id('bddf5441-1244-a49d-a125-b5fd3fb111a7')
    def test_kuryr_cni_daemon(self):
        namespace = CONF.kuryr_kubernetes.kube_system_namespace
        kube_system_pods = self.get_pod_name_list(
            namespace=namespace)
        cmd = ['cat', '/proc/1/cmdline']

        for kuryr_pod_name in kube_system_pods:
            if kuryr_pod_name.startswith('kuryr-cni'):
                self.assertIn(
                    'kuryr-daemon --config-file',
                    self.exec_command_in_pod(kuryr_pod_name, cmd, namespace,
                                             container='kuryr-cni'))
