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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base


LOG = logging.getLogger(__name__)
CONF = config.CONF

K8S_ANNOTATION_PREFIX = 'openstack.org/kuryr'

NAD_CRD_NAME = "network-attachment-definitions.k8s.cni.cncf.io"


class TestNpwgMultiVifScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestNpwgMultiVifScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.npwg_multi_vif_enabled:
            raise cls.skipException(
                "NPWG Multi-VIF feature should be enabled to run this test.")

    @decorators.idempotent_id('bddf3211-1244-449d-a125-b5fddfb1a3aa')
    def test_npwg_multi_vif(self):
        nad_name, nad = self._create_network_crd_obj()

        # create a pod with additional interfaces
        annotations = {'k8s.v1.cni.cncf.io/networks': nad_name}
        pod_name, pod = self.create_pod(annotations=annotations)
        command = ['/bin/ip', 'a']
        output = self.exec_command_in_pod(pod_name, command)
        self.assertIn('eth1', output)

        self.addCleanup(self.delete_pod, pod_name, pod)

    def _create_network_crd_obj(self, name=None, namespace='default'):
        if not name:
            name = data_utils.rand_name(prefix='net')

        self.new_net = self._create_network()
        self.new_subnet = self.create_subnet(network=self.new_net)
        subnet_id = self.new_subnet['id']
        self.nad_obj_manifest = {
            'apiVersion': 'k8s.cni.cncf.io/v1',
            'kind': 'NetworkAttachmentDefinition',
            'metadata':
                {
                    'name': name,
                    'annotations': {
                        'openstack.org/kuryr-config':
                            '{"subnetId": "' + subnet_id + '"}'
                    }
                }
        }
        version = 'v1'
        group = 'k8s.cni.cncf.io'
        plural = 'network-attachment-definitions'

        custom_obj_api = self.k8s_client.CustomObjectsApi()
        obj = custom_obj_api.create_namespaced_custom_object(
            group, version, namespace, plural, self.nad_obj_manifest
        )
        body = self.k8s_client.V1DeleteOptions()
        self.addCleanup(custom_obj_api.delete_namespaced_custom_object,
                        group, version, namespace, plural, name, body)
        return name, obj
