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

import abc
import time

import kubernetes
from kubernetes import client as k8s_client
import netaddr

from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from kuryr_tempest_plugin.tests.scenario import base
from kuryr_tempest_plugin.tests.scenario import consts

LOG = logging.getLogger(__name__)
CONF = config.CONF

TIMEOUT_PERIOD = 180


class TestNetworkPolicyScenario(base.BaseKuryrScenarioTest,
                                metaclass=abc.ABCMeta):

    @classmethod
    def skip_checks(cls):
        super(TestNetworkPolicyScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.network_policy_enabled:
            raise cls.skipException('Network Policy driver and handler must '
                                    'be enabled to run this tests')

    def get_sg_rules_for_np(self, namespace, network_policy_name):
        start = time.time()
        sg_id = None
        ready = False
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(consts.NP_CHECK_SLEEP_TIME)
                sg_id, _, ready = self.get_np_crd_info(
                    name=network_policy_name, namespace=namespace)
                if sg_id and ready:
                    break
            except kubernetes.client.rest.ApiException:
                continue
        self.assertIsNotNone(sg_id)
        self.assertTrue(ready)
        return self.list_security_group_rules(sg_id)

    def check_sg_rules_for_np(self, namespace, np,
                              ingress_cidrs_should_exist=(),
                              egress_cidrs_should_exist=(),
                              ingress_cidrs_shouldnt_exist=(),
                              egress_cidrs_shouldnt_exist=()):
        ingress_cidrs_should_exist = set(ingress_cidrs_should_exist)
        egress_cidrs_should_exist = set(egress_cidrs_should_exist)
        ingress_cidrs_shouldnt_exist = set(ingress_cidrs_shouldnt_exist)
        egress_cidrs_shouldnt_exist = set(egress_cidrs_shouldnt_exist)

        rules_match = False
        start = time.time()

        while not rules_match and (time.time() - start) < TIMEOUT_PERIOD:
            ingress_cidrs_found = set()
            egress_cidrs_found = set()
            sg_rules = self.get_sg_rules_for_np(namespace, np)

            for rule in sg_rules:
                if rule['direction'] == 'ingress':
                    ingress_cidrs_found.add(rule['remote_ip_prefix'])
                elif rule['direction'] == 'egress':
                    egress_cidrs_found.add(rule['remote_ip_prefix'])

            if (ingress_cidrs_should_exist.issubset(ingress_cidrs_found)
                and (not ingress_cidrs_shouldnt_exist
                     or not ingress_cidrs_shouldnt_exist.issubset(
                            ingress_cidrs_found))
                and egress_cidrs_should_exist.issubset(egress_cidrs_found)
                and (not egress_cidrs_shouldnt_exist
                     or not egress_cidrs_shouldnt_exist.issubset(
                            egress_cidrs_found))):
                rules_match = True

            time.sleep(consts.NP_CHECK_SLEEP_TIME)

        if not rules_match:
            msg = 'Timed out waiting sg rules for np %s to match' % np
            raise lib_exc.TimeoutException(msg)

    @abc.abstractmethod
    def get_np_crd_info(self, name, namespace='default', **kwargs):
        pass

    @decorators.idempotent_id('a9db5bc5-e921-4719-8201-5431537c86f8')
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
        ready = False
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(consts.NP_CHECK_SLEEP_TIME)
                sg_id, _, ready = self.get_np_crd_info(
                    network_policy_name, namespace=namespace_name)
                if sg_id and ready:
                    break
            except kubernetes.client.rest.ApiException:
                continue
        self.assertIsNotNone(sg_id)
        self.assertTrue(ready)
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
        pod_name, pod = self.create_pod(namespace=namespace_name)
        self.addCleanup(self.delete_pod, pod_name, pod,
                        namespace=namespace_name)

        if CONF.kuryr_kubernetes.kuryrnetworks:
            cidr = self.get_kuryr_network_crds(
                namespace_name)['status']['subnetCIDR']
        else:
            crd_name = 'ns-' + namespace_name
            cidr = self.get_kuryr_net_crds(
                crd_name)['spec']['subnetCIDR']

        ipn = netaddr.IPNetwork(cidr)
        max_prefixlen = "/32"
        if ipn.version == 6:
            max_prefixlen = "/128"

        curl_tmpl = self.get_curl_template(cidr, extra_args='-m 5', port=True)

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
                time.sleep(consts.NP_CHECK_SLEEP_TIME)
                sg_id, _, _ = self.get_np_crd_info(network_policy_name,
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
                time.sleep(consts.NP_CHECK_SLEEP_TIME)
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
                time.sleep(consts.NP_CHECK_SLEEP_TIME)
                sg_id, _, _ = self.get_np_crd_info(network_policy_name)
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
            time.sleep(consts.NP_CHECK_SLEEP_TIME)
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
                time.sleep(consts.NP_CHECK_SLEEP_TIME)
                _, crd_pod_selector, _ = self.get_np_crd_info(
                    network_policy_name)
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
                time.sleep(consts.NP_CHECK_SLEEP_TIME)
                _, crd_pod_selector, _ = self.get_np_crd_info(
                    network_policy_name)
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
                time.sleep(consts.NP_CHECK_SLEEP_TIME)
                sg_id, _, _ = self.get_np_crd_info(network_policy_name,
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
            time.sleep(consts.NP_CHECK_SLEEP_TIME)
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
            time.sleep(consts.NP_CHECK_SLEEP_TIME)
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
                time.sleep(consts.NP_CHECK_SLEEP_TIME)
                sg_id, _, _ = self.get_np_crd_info(network_policy_name,
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
            time.sleep(consts.NP_CHECK_SLEEP_TIME)
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
            time.sleep(consts.NP_CHECK_SLEEP_TIME)
        if time.time() - start >= TIMEOUT_PERIOD:
            raise lib_exc.TimeoutException('Sec group ID still exists')

    @decorators.idempotent_id('a93b5bc5-e931-4719-8201-54315c5c86f8')
    def test_network_policy_add_remove_pod(self):
        np_name_server = 'allow-all-server'
        np_name_client = 'allow-all-client'
        server_label = {'app': 'server'}
        client_label = {'app': 'client'}
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)

        self.create_setup_for_service_test(label='server',
                                           namespace=namespace_name,
                                           cleanup=False)
        LOG.debug("A service %s and two pods were created in namespace %s",
                  self.service_name, namespace_name)
        service_pods = self.get_pod_list(namespace=namespace_name,
                                         label_selector='app=server')
        service_pods_cidrs = [pod.status.pod_ip+'/32' for pod in service_pods]
        (first_server_pod_cidr, first_server_pod_name) = (
         service_pods[0].status.pod_ip+"/32",
         service_pods[0].metadata.name)
        client_pod_name = self.check_service_internal_connectivity(
            namespace=namespace_name,
            labels=client_label,
            cleanup=False)
        client_pod_ip = self.get_pod_ip(client_pod_name,
                                        namespace=namespace_name)
        client_pod_cidr = client_pod_ip + "/32"
        LOG.debug("Client pod %s was created", client_pod_name)
        LOG.debug("Connection to service %s from %s was successful",
                  self.service_name, client_pod_name)
        # Check connectivity in the same namespace
        connect_to_service_cmd = ["/bin/sh", "-c", "curl {dst_ip}".format(
                                  dst_ip=self.service_ip)]
        blocked_pod, _ = self.create_pod(namespace=namespace_name)
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(blocked_pod,
                                               connect_to_service_cmd,
                                               namespace_name))

        pods_server_match_expression = {'key': 'app',
                                        'operator': 'In',
                                        'values': ['server']}
        pods_client_match_expression = {'key': 'app',
                                        'operator': 'In',
                                        'values': ['client']}
        np_server = self.create_network_policy(
            name=np_name_server,
            namespace=namespace_name,
            match_labels=server_label,
            ingress_match_expressions=[pods_client_match_expression],
            egress_match_expressions=[pods_client_match_expression])
        LOG.debug("Network policy %s with match expression %s was created",
                  np_server, pods_server_match_expression)
        self.addCleanup(self.delete_network_policy, np_server.metadata.name,
                        namespace_name)
        np_client = self.create_network_policy(
            name=np_name_client,
            namespace=namespace_name,
            match_labels=client_label,
            ingress_match_expressions=[pods_server_match_expression],
            egress_match_expressions=[pods_server_match_expression])
        LOG.debug("Network policy %s with match expression %s was created",
                  np_client, pods_client_match_expression)
        self.addCleanup(self.delete_network_policy, np_client.metadata.name,
                        namespace_name)
        self.check_sg_rules_for_np(
                namespace_name, np_name_server,
                ingress_cidrs_should_exist=[client_pod_cidr],
                egress_cidrs_should_exist=[client_pod_cidr],
                ingress_cidrs_shouldnt_exist=[],
                egress_cidrs_shouldnt_exist=[])
        self.check_sg_rules_for_np(
                namespace_name, np_name_client,
                ingress_cidrs_should_exist=service_pods_cidrs,
                egress_cidrs_should_exist=service_pods_cidrs,
                ingress_cidrs_shouldnt_exist=[],
                egress_cidrs_shouldnt_exist=[])
        self.check_service_internal_connectivity(namespace=namespace_name,
                                                 pod_name=client_pod_name)
        LOG.debug("Connection to service %s from %s was successful after "
                  "network policy was applied",
                  self.service_name, client_pod_name)

        # Check no connectivity from a pod not in the NP
        self.assertNotIn(consts.POD_OUTPUT,
                         self.exec_command_in_pod(blocked_pod,
                                                  connect_to_service_cmd,
                                                  namespace_name))

        self.delete_pod(first_server_pod_name, namespace=namespace_name)
        LOG.debug("Deleted pod %s from service %s",
                  first_server_pod_name, self.service_name)
        self.verify_lbaas_endpoints_configured(self.service_name,
                                               1, namespace_name)
        self.check_service_internal_connectivity(namespace=namespace_name,
                                                 pod_name=client_pod_name,
                                                 pod_num=1)
        LOG.debug("Connection to service %s with one pod from %s was "
                  "successful", self.service_name, client_pod_name)
        # Check that the deleted pod is removed from SG rules
        self.check_sg_rules_for_np(
            namespace_name, np_name_client,
            ingress_cidrs_shouldnt_exist=[
                first_server_pod_cidr],
            egress_cidrs_shouldnt_exist=[
                first_server_pod_cidr])

        pod_name, pod = self.create_pod(labels=server_label,
                                        namespace=namespace_name)
        LOG.debug("Pod server %s with label %s was created",
                  pod_name, server_label)
        self.verify_lbaas_endpoints_configured(self.service_name,
                                               2, namespace_name)
        service_pods = self.get_pod_list(namespace=namespace_name,
                                         label_selector='app=server')
        service_pods_cidrs = [pod.status.pod_ip+'/32' for pod in service_pods]
        self.check_sg_rules_for_np(
            namespace_name, np_name_server,
            ingress_cidrs_should_exist=[client_pod_cidr],
            egress_cidrs_should_exist=[client_pod_cidr],
            ingress_cidrs_shouldnt_exist=[],
            egress_cidrs_shouldnt_exist=[])
        self.check_sg_rules_for_np(
            namespace_name, np_name_client,
            ingress_cidrs_should_exist=service_pods_cidrs,
            egress_cidrs_should_exist=service_pods_cidrs)
        self.check_service_internal_connectivity(namespace=namespace_name,
                                                 pod_name=client_pod_name)
        LOG.debug("Connection to service %s from %s was successful",
                  self.service_name, client_pod_name)
        # Check no connectivity from a pod not in the NP
        self.assertNotIn(consts.POD_OUTPUT,
                         self.exec_command_in_pod(blocked_pod,
                                                  connect_to_service_cmd,
                                                  namespace_name))

    @decorators.idempotent_id('ee018bf6-2d5d-4c4e-8c79-793f4772852f')
    def test_network_policy_hairpin_traffic(self):
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)
        svc_name, svc_pods = self.create_setup_for_service_test(
            namespace=namespace_name, cleanup=False, save=False, pod_num=1)
        self.check_service_internal_connectivity(
            namespace=namespace_name, pod_num=1, service_name=svc_name,
            pod_name=svc_pods[0])
        policy_name = data_utils.rand_name(prefix='kuryr-policy')

        np = k8s_client.V1NetworkPolicy(
            kind='NetworkPolicy',
            api_version='networking.k8s.io/v1',
            metadata=k8s_client.V1ObjectMeta(
                name=policy_name,
                namespace=namespace_name),
            spec=k8s_client.V1NetworkPolicySpec(
                pod_selector=k8s_client.V1LabelSelector(),
                policy_types=['Egress', 'Ingress'],
                ingress=[
                    k8s_client.V1NetworkPolicyIngressRule(
                        _from=[
                            k8s_client.V1NetworkPolicyPeer(
                                pod_selector=k8s_client.V1LabelSelector(),
                            ),
                        ],
                    ),
                ],
                egress=[
                    k8s_client.V1NetworkPolicyEgressRule(
                        to=[
                            k8s_client.V1NetworkPolicyPeer(
                                pod_selector=k8s_client.V1LabelSelector(),
                            ),
                        ],
                    ),
                ],
            ),
        )

        k8s_client.NetworkingV1Api().create_namespaced_network_policy(
            namespace=namespace_name, body=np)
        # Just to wait for SGs.
        self.get_sg_rules_for_np(namespace_name, policy_name)
        self.check_service_internal_connectivity(
            namespace=namespace_name, pod_num=1, service_name=svc_name,
            pod_name=svc_pods[0])
