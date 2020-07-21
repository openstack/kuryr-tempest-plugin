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

from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base
from kuryr_tempest_plugin.tests.scenario import base_network_policy as base_np

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
                crd['spec'].get('podSelector'))


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

        return (crd['status'].get('securityGroupId'),
                crd['status'].get('podSelector'))
