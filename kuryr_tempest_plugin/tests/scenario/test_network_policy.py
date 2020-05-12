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

import netaddr
from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from kuryr_tempest_plugin.tests.scenario import base
from kuryr_tempest_plugin.tests.scenario import consts

LOG = logging.getLogger(__name__)
CONF = config.CONF

TIMEOUT_PERIOD = 120


class TestNetworkPolicyScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestNetworkPolicyScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.network_policy_enabled:
            raise cls.skipException('Network Policy driver and handler must '
                                    'be enabled to run this tests')

    @decorators.idempotent_id('a9db5bc5-e921-4719-8201-5431537c86f8')
    @decorators.unstable_test(bug="1860554")
    def test_ipblock_network_policy_sg_rules(self):
        ingress_ipblock = "5.5.5.0/24"
        egress_ipblock = "4.4.4.0/24"
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)
        np = self.create_network_policy(namespace=namespace_name,
                                        ingress_ipblock_cidr=ingress_ipblock,
                                        egress_ipblock_cidr=egress_ipblock,
                                        ingress_port=2500)
        LOG.debug("Creating network policy %s", np)
        self.addCleanup(self.delete_network_policy, np.metadata.name,
                        namespace_name)
        network_policy_name = np.metadata.name
        kuryr_netpolicy_crd_name = 'np-' + network_policy_name
        kuryrnetpolicies = None
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                kuryrnetpolicies = self.get_kuryr_netpolicy_crds(
                    name=kuryr_netpolicy_crd_name,
                    namespace=namespace_name)
                break
            except kubernetes.client.rest.ApiException:
                time.sleep(1)
                continue
        self.assertIsNotNone(kuryrnetpolicies)
        sg_id = kuryrnetpolicies['spec']['securityGroupId']
        sec_group_rules = self.list_security_group_rules(sg_id)
        ingress_block_found, egress_block_found = False, False
        for rule in sec_group_rules:
            if (rule['direction'] == 'ingress' and
                    rule['remote_ip_prefix'] == ingress_ipblock):
                ingress_block_found = True
            if (rule['direction'] == 'egress' and
                    rule['remote_ip_prefix'] == egress_ipblock):
                egress_block_found = True
        self.assertTrue(ingress_block_found)
        self.assertTrue(egress_block_found)

    @decorators.idempotent_id('a9db5bc5-e921-4819-8301-5431437c76f8')
    def test_ipblock_network_policy_allow_except(self):
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)
        cidr = self.get_kuryr_network_crds(
            namespace_name)['status']['subnetCIDR']

        ipn = netaddr.IPNetwork(cidr)
        max_prefixlen = "/32"
        curl_tmpl = "curl {}{}"
        if ipn.version == 6:
            max_prefixlen = "/128"
            curl_tmpl = "curl [{}]{}"

        allow_all_cidr = cidr
        pod_ip_list = []
        pod_name_list = []
        cmd_list = []

        for i in range(4):
            pod_name, pod = self.create_pod(namespace=namespace_name)
            self.addCleanup(self.delete_pod, pod_name, pod,
                            namespace=namespace_name)
            pod_name_list.append(pod_name)
            pod_ip = self.get_pod_ip(pod_name, namespace=namespace_name)
            pod_ip_list.append(pod_ip)
            cmd = ["/bin/sh", "-c", curl_tmpl.format(pod_ip_list[i], ':8080')]
            cmd_list.append(cmd)

        # Check connectivity from pod4 to other pods before creating NP
        for i in range(3):
            self.assertIn(consts.POD_OUTPUT, self.exec_command_in_pod(
                pod_name_list[3], cmd_list[i], namespace=namespace_name))
        # Check connectivity from pod1 to pod4 before creating NP
        self.assertIn(consts.POD_OUTPUT, self.exec_command_in_pod(
            pod_name_list[0], cmd_list[3], namespace=namespace_name))

        # Create NP allowing all besides first pod on ingress
        # and second pod on egress
        np = self.create_network_policy(
            namespace=namespace_name, ingress_ipblock_cidr=allow_all_cidr,
            ingress_ipblock_except=[pod_ip_list[0] + max_prefixlen],
            egress_ipblock_cidr=allow_all_cidr,
            egress_ipblock_except=[pod_ip_list[1] + max_prefixlen])

        LOG.debug("Creating network policy %s", np)
        network_policy_name = np.metadata.name
        kuryr_netpolicy_crd_name = 'np-' + network_policy_name

        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                self.get_kuryr_netpolicy_crds(
                    name=kuryr_netpolicy_crd_name, namespace=namespace_name)
                break
            except kubernetes.client.rest.ApiException:
                time.sleep(1)
                continue

        # Wait for network policy to be created
        time.sleep(consts.TIME_TO_APPLY_SGS)

        # Check that http connection from pod1 to pod4 is blocked
        # after creating NP
        self.assertNotIn(consts.POD_OUTPUT, self.exec_command_in_pod(
            pod_name_list[0], cmd_list[3], namespace=namespace_name))

        # Check that http connection from pod4 to pod2 is blocked
        # after creating NP
        self.assertNotIn(consts.POD_OUTPUT, self.exec_command_in_pod(
            pod_name_list[3], cmd_list[1], namespace=namespace_name))

        # Check that http connection from pod4 to pod1 is not blocked
        self.assertIn(consts.POD_OUTPUT, self.exec_command_in_pod(
            pod_name_list[3], cmd_list[0], namespace=namespace_name))

        # Check that there is still http connection to pod3
        # from pod4 as it's not blocked by IPblock rules
        self.assertIn(consts.POD_OUTPUT, self.exec_command_in_pod(
            pod_name_list[3], cmd_list[2], namespace=namespace_name))

        # Delete network policy and check that there is still http connection
        # between pods
        np_exist = True
        self.delete_network_policy(np.metadata.name, namespace_name)

        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(1)
                self.get_kuryr_netpolicy_crds(
                    name=kuryr_netpolicy_crd_name, namespace=namespace_name)
            except kubernetes.client.rest.ApiException as e:
                if e.status == 404:
                    np_exist = False
                    break
                else:
                    continue
        self.assertFalse(np_exist)

        for i in range(3):
            self.assertIn(consts.POD_OUTPUT, self.exec_command_in_pod(
                pod_name_list[3], cmd_list[i], namespace=namespace_name))
        for i in range(1, 4):
            self.assertIn(consts.POD_OUTPUT, self.exec_command_in_pod(
                pod_name_list[0], cmd_list[i], namespace=namespace_name))

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

        label_key = 'context'
        match_labels = {label_key: 'demo'}
        np = self.read_network_policy(np)
        np.spec.pod_selector.match_labels = match_labels
        np = self.update_network_policy(np)

        labels = {}
        start = time.time()
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
        self.addCleanup(self.delete_namespace, ns_name)
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
        field = 'ingressSgRules'
        self._create_kuryr_net_policy_crd_obj(knp_obj, error_msg, field)

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
        field = 'security_group_rule.id'
        self._create_kuryr_net_policy_crd_obj(knp_obj, error_msg, field)

    @decorators.idempotent_id('47f0e412-3e13-40b2-93e5-503790df870b')
    def test_create_knp_crd_with_networkpolicy_spec_wrong_type(self):
        if not CONF.kuryr_kubernetes.validate_crd:
            raise self.skipException('CRD validation must be enabled to run '
                                     'this test.')
        np_name = 'test'
        knp_obj = dict(self._get_knp_obj(np_name))
        knp_obj['spec']['networkpolicy_spec'] = []
        error_msg = 'networkpolicy_spec in body must be of type object'
        field = 'networkpolicy_spec'
        self._create_kuryr_net_policy_crd_obj(knp_obj, error_msg, field)

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
                    'policyTypes': ['Ingress'],
                    'podSelector': {}},
                'podSelector': {},
                'securityGroupId': '',
                'securityGroupName': "sg-" + name}}

    def _create_kuryr_net_policy_crd_obj(self, crd_manifest, error_msg,
                                         field, namespace='default'):
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
            err_msg_cause = error_causes[0].get('message', "")
            err_field_cause = error_causes[0].get('field', "[]")
            if err_field_cause != "[]":
                self.assertTrue(field in
                                err_field_cause)
            else:
                self.assertTrue(error_msg in err_msg_cause)
        else:
            body = self.k8s_client.V1DeleteOptions()
            self.addCleanup(custom_obj_api.delete_namespaced_custom_object,
                            group, version, namespace, plural,
                            crd_manifest['metadata']['name'], body)
            raise Exception('{} for Kuryr Net Policy CRD'.format(error_msg))
