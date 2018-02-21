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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from kuryr_tempest_plugin.tests import base

from oslo_config import cfg

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class PodTest(base.BaseAdminKuryrTest):

    def _list_pods(self):
        pods = self.k8s_client.list_pod_for_all_namespaces(watch=False)
        return pods

    def _delete_pod(self, pod_name, body=None, namespace='default'):
        if body is None:
            body = {}
        self.k8s_client.delete_namespaced_pod(name=pod_name,
                                              body=body,
                                              namespace=namespace)

    @decorators.idempotent_id('b6fbd21a-d7cb-497d-b03b-02e09cc2caf8')
    def test_create_list_pod(self):
        pod_name = data_utils.rand_name('pod')
        pod_manifest = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata':
            {
                'name': pod_name
            },
            'spec': {
                'containers': [{
                    'image': 'busybox',
                    'name': 'sleep',
                    "args": [
                        "/bin/sh",
                        "-c",
                        "while true; do date; sleep 5; done"
                    ]
                }]
            }
        }
        self.k8s_client.create_namespaced_pod(body=pod_manifest,
                                              namespace='default')
        pod_names = [pod.metadata.name for pod in self._list_pods().items]
        self.assertIn(pod_name, pod_names)
        self.addCleanup(self._delete_pod, pod_name)
