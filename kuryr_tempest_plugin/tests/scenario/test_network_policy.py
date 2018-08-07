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

import kubernetes
import time

from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestNetworkPolicyScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestNetworkPolicyScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.network_policy_enabled:
            raise cls.skipException('Network Policy driver and handler must '
                                    'be enabled to run this tests')

    @decorators.idempotent_id('24577a9b-1d29-409b-8b60-da3b49d776b1')
    def test_create_delete_network_policy(self):
        np = self.create_network_policy()
        LOG.debug("Creating network policy %s" % np)
        network_policy_name = np.metadata.name
        kuryr_netpolicy_crd_name = 'np-' + network_policy_name
        network_policies = self.list_network_policies()
        kuryrnetpolicies = ''
        while True:
            try:
                kuryrnetpolicies = self.get_kuryr_netpolicy_crds(
                    name=kuryr_netpolicy_crd_name)
                break
            except kubernetes.client.rest.ApiException:
                time.sleep(1)
                continue
        sg_id = kuryrnetpolicies['spec']['securityGroupId']
        sgs = self.list_security_groups(fields='id')
        sg_ids = [sg['id'] for sg in sgs]
        self.assertIn(network_policy_name, network_policies)
        self.assertEqual(kuryr_netpolicy_crd_name,
                         str(kuryrnetpolicies['metadata']['name']))
        self.assertIn(sg_id, sg_ids)
        self.delete_network_policy(network_policy_name)
        self.assertNotIn(network_policy_name, self.list_network_policies())
        while True:
            time.sleep(1)
            try:
                self.get_kuryr_netpolicy_crds(name=kuryr_netpolicy_crd_name)
            except kubernetes.client.rest.ApiException:
                break
        sgs_after = self.list_security_groups(fields='id')
        sg_ids_after = [sg['id'] for sg in sgs_after]
        self.assertNotIn(sg_id, sg_ids_after)
