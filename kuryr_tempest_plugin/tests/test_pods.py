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


from tempest.lib import decorators

from kuryr_tempest_plugin.tests import base

from oslo_config import cfg

CONF = cfg.CONF


class PodTest(base.BaseAdminKuryrTest):

    def _list_pods(self):
        pods = self.k8s_client.list_pod_for_all_namespaces(watch=False)
        return pods

    @decorators.idempotent_id('f96b40a8-25bc-4ddd-a862-072a2b7b80b8')
    def test_list_pods(self):
        pods = self._list_pods()
        self.assertEmpty(pods.items)
