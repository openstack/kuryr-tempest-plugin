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
import time

import kubernetes

from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from kuryr_tempest_plugin.tests.scenario import base
from kuryr_tempest_plugin.tests.scenario import base_network_policy as base_np
from kuryr_tempest_plugin.tests.scenario import consts

LOG = logging.getLogger(__name__)
CONF = config.CONF

TIMEOUT_PERIOD = 120
KURYR_NET_POLICY_CRD_PLURAL = 'kuryrnetpolicies'
KURYR_NETWORK_POLICY_CRD_PLURAL = 'kuryrnetworkpolicies'


class OldNetworkPolicyScenario(base_np.TestNetworkPolicyScenario):

    @classmethod
    def skip_checks(cls):
        super(OldNetworkPolicyScenario, cls).skip_checks()
        if CONF.kuryr_kubernetes.new_kuryrnetworkpolicy_crd:
            raise cls.skipException(
                'Old KuryrNetPolicy NP CRDs must be used to run these tests')

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
                self.assertTrue(field in err_field_cause)
            else:
                self.assertTrue(error_msg in err_msg_cause)
        else:
            body = self.k8s_client.V1DeleteOptions()
            self.addCleanup(custom_obj_api.delete_namespaced_custom_object,
                            group, version, namespace, plural,
                            crd_manifest['metadata']['name'], body)
            raise Exception('{} for Kuryr Net Policy CRD'.format(error_msg))

    def get_np_crd_info(self, name, namespace='default', **kwargs):
        name = 'np-' + name
        crd = self.k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            group=base.KURYR_CRD_GROUP, version=base.KURYR_CRD_VERSION,
            namespace=namespace, plural=KURYR_NET_POLICY_CRD_PLURAL,
            name=name, **kwargs)
        return (crd['spec'].get('securityGroupId'),
                crd['spec'].get('podSelector'),
                True)


class NetworkPolicyScenario(base_np.TestNetworkPolicyScenario):

    @classmethod
    def skip_checks(cls):
        super(NetworkPolicyScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.new_kuryrnetworkpolicy_crd:
            raise cls.skipException(
                'New KuryrNetworkPolicy NP CRDs must be used to run these '
                'tests')

    def get_np_crd_info(self, name, namespace='default', **kwargs):
        crd = self.k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            group=base.KURYR_CRD_GROUP, version=base.KURYR_CRD_VERSION,
            namespace=namespace, plural=KURYR_NETWORK_POLICY_CRD_PLURAL,
            name=name, **kwargs)

        expected = len(crd['spec'].get('egressSgRules', []) +
                       crd['spec'].get('ingressSgRules', []))
        existing = len(crd['status']['securityGroupRules'])

        # Third result tells us if all the SG rules are created.
        return (crd['status'].get('securityGroupId'),
                crd['status'].get('podSelector'),
                expected == existing)


class ServiceWOSelectorsNPScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(ServiceWOSelectorsNPScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.network_policy_enabled:
            raise cls.skipException('Network Policy driver and handler must '
                                    'be enabled to run this tests')
        if not CONF.kuryr_kubernetes.test_services_without_selector:
            raise cls.skipException("Service without selectors tests are not "
                                    "enabled")
        if not CONF.kuryr_kubernetes.new_kuryrnetworkpolicy_crd:
            raise cls.skipException('New KuryrNetworkPolicy NP CRDs must be '
                                    'used to run these tests')

    def get_np_crd_info(self, name, namespace='default', **kwargs):
        crd = self.k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            group=base.KURYR_CRD_GROUP, version=base.KURYR_CRD_VERSION,
            namespace=namespace, plural=KURYR_NETWORK_POLICY_CRD_PLURAL,
            name=name, **kwargs)

        expected = len(crd['spec'].get('egressSgRules', []) +
                       crd['spec'].get('ingressSgRules', []))
        existing = len(crd['status']['securityGroupRules'])

        # Third result tells us if all the SG rules are created.
        return (crd['status'].get('securityGroupId'),
                crd['status'].get('podSelector'),
                expected == existing)

    @decorators.idempotent_id('abcfa34d-078c-485f-a80d-765c173d7652')
    def test_egress_np_to_service_wo_selectors(self):

        # create namespace for client
        client_ns_name = data_utils.rand_name(prefix='client-ns')
        client_label = {'app': data_utils.rand_name('client')}
        self.create_namespace(name=client_ns_name)
        self.addCleanup(self.delete_namespace, client_ns_name)

        # create client pod in client ns
        client_pod_name = data_utils.rand_name(prefix='client-pod')
        self.create_pod(namespace=client_ns_name, name=client_pod_name,
                        labels=client_label)

        # create ns for server
        server_ns_name = data_utils.rand_name(prefix='server-ns')
        server_label = {'app': data_utils.rand_name('server')}
        self.create_namespace(name=server_ns_name, labels=server_label)
        self.addCleanup(self.delete_namespace, server_ns_name)

        # create server pod under it
        server_pod_name = data_utils.rand_name(prefix='server-pod')
        self.create_pod(namespace=server_ns_name, name=server_pod_name,
                        labels=server_label)
        server_pod_addr = self.get_pod_ip(server_pod_name,
                                          namespace=server_ns_name)

        # create another server pod with different label
        server2_label = {'app': data_utils.rand_name('server2')}
        server2_pod_name = data_utils.rand_name(prefix='server2-pod')
        self.create_pod(namespace=server_ns_name, name=server2_pod_name,
                        labels=server2_label)
        server2_pod_addr = self.get_pod_ip(server2_pod_name,
                                           namespace=server_ns_name)

        # create service w/o selectors
        service_name, _ = self.create_service(namespace=server_ns_name,
                                              pod_label=None)
        # manually create endpoint for the service
        endpoint = self.k8s_client.V1Endpoints()
        endpoint.metadata = self.k8s_client.V1ObjectMeta(name=service_name)
        addresses = [self.k8s_client.V1EndpointAddress(ip=server_pod_addr)]
        try:
            ports = [self.k8s_client.V1EndpointPort(
                name=None, port=8080, protocol='TCP')]
        except AttributeError:
            # FIXME(dulek): kubernetes==21.7.0 renamed V1EndpointPort to
            # CoreV1EndpointPort, probably mistakenly. Bugreport:
            # https://github.com/kubernetes-client/python/issues/1661
            ports = [self.k8s_client.CoreV1EndpointPort(
                name=None, port=8080, protocol='TCP')]
        endpoint.subsets = [self.k8s_client.V1EndpointSubset(
                            addresses=addresses,
                            ports=ports)]
        self.k8s_client.CoreV1Api().create_namespaced_endpoints(
            namespace=server_ns_name, body=endpoint)

        # create another service
        service2_name, _ = self.create_service(namespace=server_ns_name,
                                               pod_label=None)

        # manually create endpoint for the service
        endpoint = self.k8s_client.V1Endpoints()
        endpoint.metadata = self.k8s_client.V1ObjectMeta(name=service2_name)
        addresses = [self.k8s_client.V1EndpointAddress(ip=server2_pod_addr)]
        try:
            ports = [self.k8s_client.V1EndpointPort(
                name=None, port=8080, protocol='TCP')]
        except AttributeError:
            # FIXME(dulek): kubernetes==21.7.0 renamed V1EndpointPort to
            # CoreV1EndpointPort, probably mistakenly. Bugreport:
            # https://github.com/kubernetes-client/python/issues/1661
            ports = [self.k8s_client.CoreV1EndpointPort(
                name=None, port=8080, protocol='TCP')]
        endpoint.subsets = [self.k8s_client.V1EndpointSubset(
                            addresses=addresses,
                            ports=ports)]
        self.k8s_client.CoreV1Api().create_namespaced_endpoints(
            namespace=server_ns_name, body=endpoint)

        # check endpoints configured
        service_ip = self.get_service_ip(service_name,
                                         namespace=server_ns_name)
        service2_ip = self.get_service_ip(service2_name,
                                          namespace=server_ns_name)
        self.verify_lbaas_endpoints_configured(service_name, 1, server_ns_name)
        self.verify_lbaas_endpoints_configured(service2_name, 1,
                                               server_ns_name)
        self.wait_until_service_LB_is_active(service_name, server_ns_name)
        self.wait_until_service_LB_is_active(service2_name, server_ns_name)

        # check connectivity
        curl_tmpl = self.get_curl_template(service_ip, extra_args='-m 10')
        cmd = ["/bin/sh", "-c", curl_tmpl.format(service_ip)]
        cmd2 = ["/bin/sh", "-c", curl_tmpl.format(service2_ip)]
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(client_pod_name, cmd,
                                               namespace=client_ns_name),
                      "Connectivity from %s to service %s (%s) failed." %
                      (client_pod_name, service_ip, service_name))
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(client_pod_name, cmd2,
                                               namespace=client_ns_name),
                      "Connectivity from %s to service2 %s (%s) failed." %
                      (client_pod_name, service2_ip, service2_name))

        # create NP for client to be able to reach server
        np_name = data_utils.rand_name(prefix='kuryr-np')
        np = self.k8s_client.V1NetworkPolicy()
        np.kind = 'NetworkPolicy'
        np.api_version = 'networking.k8s.io/v1'
        np.metadata = self.k8s_client.V1ObjectMeta(name=np_name,
                                                   namespace=client_ns_name)
        to = self.k8s_client.V1NetworkPolicyPeer(
            pod_selector=self.k8s_client.V1LabelSelector(
                match_labels=server_label),
            namespace_selector=self.k8s_client.V1LabelSelector(
                match_labels=server_label))

        np.spec = self.k8s_client.V1NetworkPolicySpec(
            pod_selector=self.k8s_client.V1LabelSelector(
                    match_labels=client_label),
            policy_types=['Egress'],
            egress=[self.k8s_client.V1NetworkPolicyEgressRule(to=[to])])

        np = (self.k8s_client.NetworkingV1Api()
              .create_namespaced_network_policy(namespace=client_ns_name,
                                                body=np))
        self.addCleanup(self.delete_network_policy, np.metadata.name,
                        client_ns_name)
        start = time.time()
        while time.time() - start < TIMEOUT_PERIOD:
            try:
                time.sleep(5)
                _, _, ready = self.get_np_crd_info(np_name, client_ns_name)
                if ready:
                    break
            except kubernetes.client.rest.ApiException as e:
                LOG.info("ApiException ocurred: %s" % e.body)
                continue
        else:
            msg = "Timed out waiting for %s %s CRD pod selector" % (
                np_name, KURYR_NETWORK_POLICY_CRD_PLURAL)
            raise lib_exc.TimeoutException(msg)

        # Even though the SG rules are up it might still take a moment until
        # they're enforced.
        time.sleep(10)

        # after applying NP, we still should have an access from client to the
        # service with matched labels,
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(client_pod_name, cmd,
                                               namespace=client_ns_name))
        # while for the other service, we should not.
        self.assertNotIn(consts.POD_OUTPUT,
                         self.exec_command_in_pod(client_pod_name, cmd2,
                                                  namespace=client_ns_name))
