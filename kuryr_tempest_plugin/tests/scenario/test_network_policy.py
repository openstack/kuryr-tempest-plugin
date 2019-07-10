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

import json
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
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
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
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            time.sleep(1)
            if network_policy_name in self.list_network_policies():
                continue
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

    @decorators.idempotent_id('24577a9b-1d29-409b-8b60-da3c49d777c2')
    def test_delete_namespace_with_network_policy(self):
        ns_name, ns = self.create_namespace()
        match_labels = {'role': 'db'}
        np = self.create_network_policy(match_labels=match_labels,
                                        namespace=ns_name)
        LOG.debug("Creating network policy %s" % np)
        network_policy_name = np.metadata.name
        kuryr_netpolicy_crd_name = 'np-' + network_policy_name
        network_policies = self.list_network_policies(namespace=ns_name)
        kuryrnetpolicies = ''
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                kuryrnetpolicies = self.get_kuryr_netpolicy_crds(
                    name=kuryr_netpolicy_crd_name, namespace=ns_name)
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

        # delete namespace
        self.delete_namespace(ns_name)
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            time.sleep(1)
            if network_policy_name in self.list_network_policies(
                    namespace=ns_name):
                continue
            try:
                self.get_kuryr_netpolicy_crds(name=kuryr_netpolicy_crd_name,
                                              namespace=ns_name)
            except kubernetes.client.rest.ApiException:
                break
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            sgs_after = self.list_security_groups(fields='id')
            sg_ids_after = [sg['id'] for sg in sgs_after]
            if sg_id not in sg_ids_after:
                break
            time.sleep(1)
        if time.time() - start >= TIMEOUT_PERIOD:
            raise lib_exc.TimeoutException('Sec group ID still exists')

    @decorators.idempotent_id('24577a9b-1d46-419b-8b60-da3c49d777c3')
    def test_create_delete_network_policy_non_default_ns(self):
        ns_name, ns = self.create_namespace()
        match_labels = {'role': 'db'}
        np = self.create_network_policy(match_labels=match_labels,
                                        namespace=ns_name)
        LOG.debug("Creating network policy %s" % np)
        network_policy_name = np.metadata.name
        kuryr_netpolicy_crd_name = 'np-' + network_policy_name
        network_policies = self.list_network_policies(namespace=ns_name)
        kuryrnetpolicies = ''
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                kuryrnetpolicies = self.get_kuryr_netpolicy_crds(
                    name=kuryr_netpolicy_crd_name, namespace=ns_name)
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
        self.delete_network_policy(network_policy_name, namespace=ns_name)
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            time.sleep(1)
            if network_policy_name in self.list_network_policies(
                    namespace=ns_name):
                continue
            try:
                self.get_kuryr_netpolicy_crds(name=kuryr_netpolicy_crd_name,
                                              namespace=ns_name)
            except kubernetes.client.rest.ApiException:
                break
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            sgs_after = self.list_security_groups(fields='id')
            sg_ids_after = [sg['id'] for sg in sgs_after]
            if sg_id not in sg_ids_after:
                break
            time.sleep(1)
        if time.time() - start >= TIMEOUT_PERIOD:
            raise lib_exc.TimeoutException('Sec group ID still exists')

    @decorators.idempotent_id('09a24a0f-322a-40ea-bb89-5b2246c8725d')
    def test_create_knp_crd_without_ingress_rules(self):
        if not CONF.kuryr_kubernetes.validate_crd:
            raise self.skipException('CRD validation must be enabled to run '
                                     'this test.')
        np_name = 'test'
        knp_obj = dict(self._get_knp_obj(np_name))
        del knp_obj['spec']['ingressSgRules']
        error_msg = 'ingressSgRules in body is required'
        self._create_kuryr_net_policy_crd_obj(knp_obj, error_msg)

    @decorators.idempotent_id('f036d26e-f603-4d00-ad92-b409b5a3ee6c')
    def test_create_knp_crd_without_sg_rule_id(self):
        if not CONF.kuryr_kubernetes.validate_crd:
            raise self.skipException('CRD validation must be enabled to run '
                                     'this test.')
        np_name = 'test'
        sg_rule = dict(self._get_sg_rule())
        del sg_rule['id']
        knp_obj = self._get_knp_obj(np_name, sg_rule)
        error_msg = 'security_group_rule.id in body is required'
        self._create_kuryr_net_policy_crd_obj(knp_obj, error_msg)

    @decorators.idempotent_id('47f0e412-3e13-40b2-93e5-503790df870b')
    def test_create_knp_crd_with_networkpolicy_spec_wrong_type(self):
        if not CONF.kuryr_kubernetes.validate_crd:
            raise self.skipException('CRD validation must be enabled to run '
                                     'this test.')
        np_name = 'test'
        knp_obj = dict(self._get_knp_obj(np_name))
        knp_obj['spec']['networkpolicy_spec'] = []
        error_msg = 'networkpolicy_spec in body must be of type object'
        self._create_kuryr_net_policy_crd_obj(knp_obj, error_msg)

    def _get_sg_rule(self):
        return {
            'description': 'kuryr-kubernetes netpolicy sg rule',
            'direction': 'egress',
            'ethertype': 'ipv4',
            'id': '',
            'security_group_id': ''
        }

    def _get_knp_obj(self, name, sg_rule=None, namespace='default'):
        if not sg_rule:
            sg_rule = self._get_sg_rule()
        return {
            'apiVersion': 'openstack.org/v1',
            'kind': 'KuryrNetPolicy',
            'metadata':
                {
                    'name': "np-" + name,
                    'annotations': {
                        'networkpolicy_name': name,
                        'networkpolicy_namespace': namespace,
                        'networkpolicy_uid': ''
                    }
                },
            'spec': {
                'egressSgRules': [{'security_group_rule': sg_rule}],
                'ingressSgRules': [],
                'networkpolicy_spec': {
                    'podSelector': {},
                    'policyTypes': ['Ingress'],
                    'podSelector': {}},
                'podSelector': {},
                'securityGroupId': '',
                'securityGroupName': "sg-" + name}}

    def _create_kuryr_net_policy_crd_obj(self, crd_manifest, error_msg,
                                         namespace='default'):
        version = 'v1'
        group = 'openstack.org'
        plural = 'kuryrnetpolicies'

        custom_obj_api = self.k8s_client.CustomObjectsApi()
        try:
            custom_obj_api.create_namespaced_custom_object(
                group, version, namespace, plural, crd_manifest)
        except kubernetes.client.rest.ApiException as e:
            self.assertEqual(e.status, 422)
            error_body = json.loads(e.body)
            error_causes = error_body['details']['causes']
            self.assertTrue(error_msg in
                            error_causes[0]['message'])
        else:
            body = self.k8s_client.V1DeleteOptions()
            self.addCleanup(custom_obj_api.delete_namespaced_custom_object,
                            group, version, namespace, plural,
                            crd_manifest['metadata']['name'], body)
            raise Exception('{} for Kuryr Net Policy CRD'.format(error_msg))
