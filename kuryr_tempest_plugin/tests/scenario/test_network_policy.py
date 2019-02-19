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
from tempest.lib import exceptions as lib_exc

from kuryr_tempest_plugin.tests.scenario import base

LOG = logging.getLogger(__name__)
CONF = config.CONF

TIMEOUT_PERIOD = 20


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

    @decorators.idempotent_id('44daf8fe-6a4b-4ca9-8685-97fb1f573e5e')
    def test_update_network_policy(self):
        """Update a Network Policy with a new pod selector

        This method creates a Network Policy with a specific pod selector
        and updates it with a new pod selector. The CRD should always have
        the same pod selector as the Policy.
        """

        match_labels = {'app': 'demo'}
        np = self.create_network_policy(match_labels=match_labels)
        self.addCleanup(self.delete_network_policy,
                        np.metadata.name)
        kuryr_netpolicy_crd_name = 'np-' + np.metadata.name
        kuryrnetpolicies = ''
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                kuryrnetpolicies = self.get_kuryr_netpolicy_crds(
                    name=kuryr_netpolicy_crd_name)
                break
            except kubernetes.client.rest.ApiException:
                time.sleep(1)
                continue
        if not kuryrnetpolicies:
            raise lib_exc.TimeoutException()

        crd_pod_selector = kuryrnetpolicies['spec']['podSelector']
        self.assertEqual(crd_pod_selector.get('matchLabels'),
                         match_labels)

        match_labels = {'context': 'demo'}
        np = self.read_network_policy(np)
        np.spec.pod_selector.match_labels = match_labels
        np = self.update_network_policy(np)

        labels = {}
        start = time.time()
        label_key = match_labels.keys()[0]
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(1)
                updated_knp = self.get_kuryr_netpolicy_crds(
                    name=kuryr_netpolicy_crd_name)
                crd_pod_selector = updated_knp['spec']['podSelector']
                labels = crd_pod_selector.get('matchLabels')
                if labels.get(label_key):
                    break
            except kubernetes.client.rest.ApiException:
                continue

        if not labels.get(label_key):
            raise lib_exc.TimeoutException()

        self.assertEqual(labels, match_labels)
