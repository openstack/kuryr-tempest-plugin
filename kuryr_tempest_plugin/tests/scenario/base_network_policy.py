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
        sg_id = None
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(1)
                sg_id, _ = self.get_np_crd_info(network_policy_name,
                                                namespace=namespace_name)
                if sg_id:
                    break
            except kubernetes.client.rest.ApiException:
                continue
        self.assertIsNotNone(sg_id)
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
        if CONF.kuryr_kubernetes.kuryrnetworks:
            cidr = self.get_kuryr_network_crds(
                namespace_name)['status']['subnetCIDR']
        else:
            crd_name = 'ns-' + namespace_name
            cidr = self.get_kuryr_net_crds(
                crd_name)['spec']['subnetCIDR']

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

        sg_id = None
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(1)
                sg_id, _ = self.get_np_crd_info(network_policy_name,
                                                namespace=namespace_name)
                if sg_id:
                    break
            except kubernetes.client.rest.ApiException:
                continue
        if not sg_id:
            msg = ('Timed out waiting for knp %s creation' %
                   network_policy_name)
            raise lib_exc.TimeoutException(msg)

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
        self.delete_network_policy(np.metadata.name, namespace_name)

        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(1)
                self.get_np_crd_info(network_policy_name,
                                     namespace=namespace_name)
            except kubernetes.client.rest.ApiException as e:
                if e.status == 404:
                    break
                else:
                    continue
        else:
            msg = ('Timed out waiting for knp %s deletion' %
                   network_policy_name)
            raise lib_exc.TimeoutException(msg)

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
        network_policies = self.list_network_policies()
        sg_id = None
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(1)
                sg_id, _ = self.get_np_crd_info(network_policy_name)
                if sg_id:
                    break
            except kubernetes.client.rest.ApiException:
                continue
        self.assertIsNotNone(sg_id)
        sgs = self.list_security_groups(fields='id')
        sg_ids = [sg['id'] for sg in sgs]
        self.assertIn(network_policy_name, network_policies)
        self.assertIn(sg_id, sg_ids)
        self.delete_network_policy(network_policy_name)
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            time.sleep(1)
            if network_policy_name in self.list_network_policies():
                continue
            try:
                self.get_np_crd_info(network_policy_name)
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
        self.addCleanup(self.delete_network_policy, np.metadata.name)
        network_policy_name = np.metadata.name
        crd_pod_selector = None

        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(1)
                _, crd_pod_selector = self.get_np_crd_info(network_policy_name)
                if crd_pod_selector:
                    break
            except kubernetes.client.rest.ApiException:
                continue

        self.assertIsNotNone(crd_pod_selector)
        self.assertEqual(crd_pod_selector.get('matchLabels'), match_labels)

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
                _, crd_pod_selector = self.get_np_crd_info(network_policy_name)
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
        network_policies = self.list_network_policies(namespace=ns_name)
        sg_id = None
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(1)
                sg_id, _ = self.get_np_crd_info(network_policy_name,
                                                namespace=ns_name)
                if sg_id:
                    break
            except kubernetes.client.rest.ApiException:
                continue
        sgs = self.list_security_groups(fields='id')
        sg_ids = [sg['id'] for sg in sgs]
        self.assertIn(network_policy_name, network_policies)
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
                self.get_np_crd_info(network_policy_name, namespace=ns_name)
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
        network_policies = self.list_network_policies(namespace=ns_name)
        sg_id = None
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(1)
                sg_id, _ = self.get_np_crd_info(network_policy_name,
                                                namespace=ns_name)
                if sg_id:
                    break
            except kubernetes.client.rest.ApiException:
                continue
        sgs = self.list_security_groups(fields='id')
        sg_ids = [sg['id'] for sg in sgs]
        self.assertIn(network_policy_name, network_policies)
        self.assertIn(sg_id, sg_ids)
        self.delete_network_policy(network_policy_name, namespace=ns_name)
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            time.sleep(1)
            if network_policy_name in self.list_network_policies(
                    namespace=ns_name):
                continue
            try:
                self.get_np_crd_info(network_policy_name, namespace=ns_name)
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
