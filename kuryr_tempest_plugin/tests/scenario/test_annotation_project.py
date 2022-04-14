# Copyright 2022 Troila.
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

from tempest import config
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base
from kuryr_tempest_plugin.tests.scenario import consts

CONF = config.CONF


class TestAnnotationProjectScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestAnnotationProjectScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.annotation_project_driver:
            raise cls.skipException('Annotation project driver must be '
                                    'enabled to run these tests')

    @classmethod
    def resource_setup(cls):
        super(TestAnnotationProjectScenario, cls).resource_setup()
        cls.project_id = cls.os_primary.projects_client.project_id

    @decorators.idempotent_id('edb10a26-4572-4565-80e4-af16af4186d3')
    def test_create_namespace_and_pod(self):
        annotations = {consts.K8s_ANNOTATION_PROJECT: self.project_id}
        namespace_name, namespace = self.create_namespace(
            annotations=annotations)
        # Ensure the namespace can be cleaned up upon tests finishing
        self.namespaces.append(namespace)

        pod_name, _ = self.create_pod(labels={"app": 'pod-label'},
                                      namespace=namespace_name)
        self.wait_for_kuryr_resource(
            namespace_name, consts.KURYR_PORT_CRD_PLURAL,
            pod_name, status_key='vifs')

        if CONF.kuryr_kubernetes.kuryrnetworks:
            kuryr_net_crd = self.get_kuryr_network_crds(namespace_name)
            subnet = self.os_admin.subnets_client.show_subnet(
                subnet_id=kuryr_net_crd['status']['subnetId'])
            self.assertEqual(subnet['subnet']['project_id'], self.project_id)
            network = self.os_admin.networks_client.show_network(
                kuryr_net_crd['status']['netId'])
            self.assertEqual(network['network']['project_id'], self.project_id)

        ports = self.os_admin.ports_client.list_ports(
            **{'project_id': self.project_id, 'device_owner': 'compute:kuryr'})
        self.assertTrue(len(ports['ports']) > 0)

    def test_create_service(self):
        if not CONF.kuryr_kubernetes.kuryrloadbalancers:
            raise self.skipException("Kuryrloadbalancers CRD should be "
                                     "used to run this test.")
        annotations = {consts.K8s_ANNOTATION_PROJECT: self.project_id}
        namespace_name, namespace = self.create_namespace(
            annotations=annotations)
        self.namespaces.append(namespace)
        service_name, pods = self.create_setup_for_service_test(
            namespace=namespace_name)
        kuryr_loadbalancer_crd = self.wait_for_kuryr_resource(
            namespace_name, consts.KURYR_LOAD_BALANCER_CRD_PLURAL,
            service_name, status_key='loadbalancer')
        lb = self.lbaas.show_loadbalancer(
            kuryr_loadbalancer_crd['status']['loadbalancer']['id'])
        self.assertEqual(lb['project_id'], self.project_id)

    def test_create_network_policy(self):
        if not CONF.kuryr_kubernetes.network_policy_enabled:
            raise self.skipException("Network policy handler and driver "
                                     "should be used to run this test.")
        annotations = {consts.K8s_ANNOTATION_PROJECT: self.project_id}
        namespace_name, namespace = self.create_namespace(
            annotations=annotations)
        self.namespaces.append(namespace)
        self.create_network_policy(
            name='network-policy', namespace=namespace_name)
        kuryr_network_policy_crd = self.wait_for_kuryr_resource(
            namespace_name, consts.KURYR_NETWORK_POLICY_CRD_PLURAL,
            'network-policy', status_key="securityGroupId")
        sg_id = kuryr_network_policy_crd['status']['securityGroupId']
        security_group = \
            self.os_admin.security_groups_client.show_security_group(sg_id)
        self.assertEqual(security_group['security_group']['project_id'],
                         self.project_id)
