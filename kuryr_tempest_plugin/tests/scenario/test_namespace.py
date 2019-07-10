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
import requests
import time

from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base
from kuryr_tempest_plugin.tests.scenario import consts

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestNamespaceScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestNamespaceScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.namespace_enabled:
            raise cls.skipException('Namespace driver and handler must be '
                                    'enabled to run this tests')

    @classmethod
    def setup_clients(cls):
        super(TestNamespaceScenario, cls).setup_clients()

    @decorators.idempotent_id('bddd5441-1244-429d-a125-b53ddfb132a9')
    def test_namespace(self):
        # Check resources are created
        namespace_name, namespace = self.create_namespace()

        existing_namespaces = [ns.metadata.name
                               for ns in self.list_namespaces().items]

        self.assertIn(namespace_name, existing_namespaces)

        subnet_name = 'ns/' + namespace_name + '-subnet'
        kuryr_net_crd_name = 'ns-' + namespace_name

        seen_subnets = self.os_admin.subnets_client.list_subnets()
        seen_subnet_names = [n['name'] for n in seen_subnets['subnets']]

        self.assertIn(subnet_name, seen_subnet_names)

        subnet_id = [n['id'] for n in seen_subnets['subnets']
                     if n['name'] == subnet_name]
        net_id = [n['network_id'] for n in seen_subnets['subnets']
                  if n['name'] == subnet_name]

        kuryr_net_crd = self.get_kuryr_net_crds(kuryr_net_crd_name)

        self.assertIn(kuryr_net_crd_name, kuryr_net_crd['metadata']['name'])
        self.assertIn(kuryr_net_crd['spec']['subnetId'], subnet_id)
        self.assertIn(kuryr_net_crd['spec']['netId'], net_id)

        # Check namespace pod connectivity
        pod_name, pod = self.create_pod(labels={"app": 'pod-label'},
                                        namespace=namespace_name)
        svc_name, _ = self.create_service(pod_label=pod.metadata.labels,
                                          spec_type='LoadBalancer',
                                          namespace=namespace_name)
        svc_service_ip = self.get_service_ip(service_name=svc_name,
                                             spec_type='LoadBalancer',
                                             namespace=namespace_name)
        self.wait_service_status(svc_service_ip,
                                 CONF.kuryr_kubernetes.lb_build_timeout)

        requests.get("http://{dst_ip}".format(dst_ip=svc_service_ip))

        # Check resources are deleted
        self._delete_namespace_resources(namespace_name, kuryr_net_crd,
                                         subnet_name)

    @decorators.idempotent_id('bdde5441-1b44-449d-a125-b5fdbfb1a2a9')
    def test_namespace_sg_isolation(self):
        # Check security group resources are created
        ns1_name, ns1 = self.create_namespace()
        ns2_name, ns2 = self.create_namespace()

        existing_namespaces = [ns.metadata.name
                               for ns in self.list_namespaces().items]
        seen_sgs = self.list_security_groups()
        seen_sg_ids = [sg['id'] for sg in seen_sgs]

        subnet_ns1_name, net_crd_ns1 = self._get_and_check_ns_resources(
            ns1_name, existing_namespaces, seen_sg_ids)
        subnet_ns2_name, net_crd_ns2 = self._get_and_check_ns_resources(
            ns2_name, existing_namespaces, seen_sg_ids)
        self.assertIn('default', existing_namespaces)

        # Create pods in different namespaces
        pod_ns1_name, pod_ns1 = self.create_pod(labels={"app": 'pod-label'},
                                                namespace=ns1_name)

        pod_ns2_name, pod_ns2 = self.create_pod(labels={"app": 'pod-label'},
                                                namespace=ns2_name)

        pod_nsdefault_name, pod_nsdefault = self.create_pod(
            labels={"app": 'pod-label'}, namespace='default')
        self.addCleanup(self.delete_pod, pod_nsdefault_name)

        # Check namespace pod connectivity and isolation
        pod_ns2_ip = self.get_pod_ip(pod_ns2_name, ns2_name)
        pod_nsdefault_ip = self.get_pod_ip(pod_nsdefault_name)

        # check connectivity from NS1 to default
        cmd = ["/bin/sh", "-c", "curl {dst_ip}:8080".format(
            dst_ip=pod_nsdefault_ip)]
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(pod_ns1_name, cmd, ns1_name))

        # check no connectivity from NS1 to NS2
        cmd = ["/bin/sh", "-c", "curl {dst_ip}:8080".format(
            dst_ip=pod_ns2_ip)]
        self.assertNotIn(consts.POD_OUTPUT,
                         self.exec_command_in_pod(pod_ns1_name, cmd, ns1_name))

        # check connectivity from default to NS2
        cmd = ["/bin/sh", "-c", "curl {dst_ip}:8080".format(
            dst_ip=pod_ns2_ip)]
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(pod_nsdefault_name, cmd))

        self._delete_namespace_resources(ns1_name, net_crd_ns1,
                                         subnet_ns1_name)
        self._delete_namespace_resources(ns2_name, net_crd_ns2,
                                         subnet_ns2_name)

    def _get_and_check_ns_resources(self, ns_name, existing_namespaces,
                                    existing_sgs):
        subnet_ns_name = 'ns/' + ns_name + '-subnet'
        net_crd_ns_name = 'ns-' + ns_name
        self.assertIn(ns_name, existing_namespaces)

        net_crd_ns = self.get_kuryr_net_crds(net_crd_ns_name)
        self.assertIn(net_crd_ns_name, net_crd_ns['metadata']['name'])
        self.assertIn(net_crd_ns['spec']['sgId'], existing_sgs)

        return subnet_ns_name, net_crd_ns

    def _create_ns_resources(self, namespace, labels=None,
                             spec_type='ClusterIP', checking_pod=None):
        pod_name, pod_ns = self.create_pod(labels=labels, namespace=namespace)
        svc_name, _ = self.create_service(pod_label=pod_ns.metadata.labels,
                                          spec_type=spec_type,
                                          namespace=namespace)
        svc_ip = self.get_service_ip(service_name=svc_name,
                                     spec_type=spec_type,
                                     namespace=namespace)
        # Wait for service to be ready
        if checking_pod:
            self.assert_backend_amount_from_pod(
                'http://{}'.format(svc_ip), 1, checking_pod,
                namespace_name='default')
        else:
            self.assert_backend_amount_from_pod(
                'http://{}'.format(svc_ip), 1, pod_name,
                namespace_name=namespace)
        return pod_name, svc_ip

    @decorators.idempotent_id('b43f5421-1244-449d-a125-b5fddfb1a2a9')
    def test_namespace_sg_svc_isolation(self):
        # Check security group resources are created
        ns1_name, ns1 = self.create_namespace()
        ns2_name, ns2 = self.create_namespace()

        existing_namespaces = [ns.metadata.name
                               for ns in self.list_namespaces().items]
        seen_sgs = self.list_security_groups()
        seen_sg_ids = [sg['id'] for sg in seen_sgs]

        subnet_ns1_name, net_crd_ns1 = self._get_and_check_ns_resources(
            ns1_name, existing_namespaces, seen_sg_ids)
        subnet_ns2_name, net_crd_ns2 = self._get_and_check_ns_resources(
            ns2_name, existing_namespaces, seen_sg_ids)
        self.assertIn('default', existing_namespaces)

        pod_nsdefault_name, pod_nsdefault = self.create_pod(
            labels={"app": 'pod-label'}, namespace='default')
        self.addCleanup(self.delete_pod, pod_nsdefault_name)

        # Create pods and services in different namespaces
        pod_ns1_name, svc_ns1_ip = self._create_ns_resources(
            ns1_name, labels={"app": 'pod-label'},
            checking_pod=pod_nsdefault_name)
        pod_ns2_name, svc_ns2_ip = self._create_ns_resources(
            ns2_name, labels={"app": 'pod-label'}, spec_type='LoadBalancer',
            checking_pod=pod_nsdefault_name)

        # Check namespace svc connectivity and isolation
        # check connectivity from NS1 pod to NS1 service
        cmd = ["/bin/sh", "-c", "curl {dst_ip}".format(
            dst_ip=svc_ns1_ip)]
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(pod_ns1_name, cmd, ns1_name))

        # check no connectivity from NS2 pod to NS1 service
        cmd = ["/bin/sh", "-c", "curl {dst_ip}".format(
            dst_ip=svc_ns1_ip)]
        self.assertNotIn(consts.POD_OUTPUT,
                         self.exec_command_in_pod(pod_ns2_name, cmd, ns2_name))

        # check connectivity from default pod to NS1 service
        cmd = ["/bin/sh", "-c", "curl {dst_ip}".format(
            dst_ip=svc_ns1_ip)]
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(pod_nsdefault_name, cmd))

        # check connectivity from NS1 pod to NS2 LoadBalancer type service
        cmd = ["/bin/sh", "-c", "curl {dst_ip}".format(
            dst_ip=svc_ns2_ip)]
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(pod_ns1_name, cmd, ns1_name))

        # Check resources are deleted
        self._delete_namespace_resources(ns1_name, net_crd_ns1,
                                         subnet_ns1_name)
        self._delete_namespace_resources(ns2_name, net_crd_ns2,
                                         subnet_ns2_name)

    @decorators.idempotent_id('bddd5441-1244-429d-a125-b53ddfb132a9')
    def test_host_to_namespace_pod_connectivity(self):
        # Create namespace and pod in that namespace
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)
        # Check host to namespace pod and pod to host connectivity
        pod_name, pod = self.create_pod(labels={"app": 'pod-label'},
                                        namespace=namespace_name)
        pod_ip = self.get_pod_ip(pod_name, namespace=namespace_name)
        host_ip_of_pod = self.get_host_ip_for_pod(
            pod_name, namespace=namespace_name)

        # Check connectivity to pod in the namespace from host pod resides on
        self.ping_ip_address(pod_ip)
        # check connectivity from Pod to host pod resides on
        cmd = [
            "/bin/sh", "-c", "ping -c 4 {dst_ip}>/dev/null ; echo $?".format(
                dst_ip=host_ip_of_pod)]
        self.assertEqual(self.exec_command_in_pod(
            pod_name, cmd, namespace_name), '0')

    def _delete_namespace_resources(self, namespace, net_crd, subnet):
        # Check resources are deleted
        self.delete_namespace(namespace)

        while True:
            time.sleep(1)
            try:
                self.get_kuryr_net_crds(net_crd['metadata']['name'])
            except kubernetes.client.rest.ApiException:
                break

        existing_namespaces = [ns.metadata.name
                               for ns in self.list_namespaces().items]
        self.assertNotIn(namespace, existing_namespaces)

        seen_subnets = self.os_admin.subnets_client.list_subnets()
        seen_subnet_names = [n['name'] for n in seen_subnets['subnets']]
        self.assertNotIn(subnet, seen_subnet_names)

        seen_sgs = self.list_security_groups()
        seen_sg_ids = [sg['id'] for sg in seen_sgs]
        if net_crd['spec'].get('sgId', None):
            self.assertNotIn(net_crd['spec']['sgId'], seen_sg_ids)

    @decorators.idempotent_id('90b7cb81-f80e-4ff3-9892-9e5fdcd08289')
    def test_create_kuryrnet_crd_without_net_id(self):
        if not CONF.kuryr_kubernetes.validate_crd:
            raise self.skipException('CRD validation must be enabled to run '
                                     'this test.')
        kuryrnet = dict(self._get_kuryrnet_obj())
        del kuryrnet['spec']['netId']
        error_msg = 'spec.netId in body is required'
        self._create_kuryr_net_crd_obj(kuryrnet, error_msg)

    @decorators.idempotent_id('94641749-9fdf-4fb2-a46d-064f75eac113')
    def test_create_kuryrnet_crd_with_populated_as_string(self):
        if not CONF.kuryr_kubernetes.validate_crd:
            raise self.skipException('CRD validation must be enabled to run '
                                     'this test.')
        kuryrnet = dict(self._get_kuryrnet_obj())
        kuryrnet['spec']['populated'] = 'False'
        error_msg = 'spec.populated in body must be of type boolean'
        self._create_kuryr_net_crd_obj(kuryrnet, error_msg)

    def _get_kuryrnet_obj(self):
        return {
            "apiVersion": "openstack.org/v1",
            "kind": "KuryrNet",
            "metadata": {
                "annotations": {
                    "namespaceName": "kube-system"
                },
                "name": "ns-test",
            },
            "spec": {
                "netId": "",
                "routerId": "",
                "subnetCIDR": "",
                "subnetId": ""
            }
        }

    def _create_kuryr_net_crd_obj(self, crd_manifest, error_msg):
        version = 'v1'
        group = 'openstack.org'
        plural = 'kuryrnets'

        custom_obj_api = self.k8s_client.CustomObjectsApi()
        try:
            custom_obj_api.create_cluster_custom_object(
                group, version, plural, crd_manifest)
        except kubernetes.client.rest.ApiException as e:
            self.assertEqual(e.status, 422)
            error_body = json.loads(e.body)
            error_causes = error_body['details']['causes']
            self.assertTrue(error_msg in
                            error_causes[0]['message'])
        else:
            body = self.k8s_client.V1DeleteOptions()
            self.addCleanup(custom_obj_api.delete_cluster_custom_object,
                            group, version, plural,
                            crd_manifest['metadata']['name'], body)
            raise Exception('{} for Kuryr Net CRD'.format(error_msg))
