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

        self.assertIn(ns1_name, existing_namespaces)
        self.assertIn(ns2_name, existing_namespaces)
        self.assertIn('default', existing_namespaces)

        subnet_ns1_name = 'ns/' + ns1_name + '-subnet'
        subnet_ns2_name = 'ns/' + ns2_name + '-subnet'
        net_crd_ns1_name = 'ns-' + ns1_name
        net_crd_ns2_name = 'ns-' + ns2_name

        net_crd_ns1 = self.get_kuryr_net_crds(net_crd_ns1_name)
        net_crd_ns2 = self.get_kuryr_net_crds(net_crd_ns2_name)

        self.assertIn(net_crd_ns1_name, net_crd_ns1['metadata']['name'])
        self.assertIn(net_crd_ns2_name, net_crd_ns2['metadata']['name'])

        seen_sgs = self.list_security_groups()
        seen_sg_ids = [sg['id'] for sg in seen_sgs]

        self.assertIn(net_crd_ns1['spec']['sgId'], seen_sg_ids)
        self.assertIn(net_crd_ns2['spec']['sgId'], seen_sg_ids)

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

    @decorators.idempotent_id('b43f5421-1244-449d-a125-b5fddfb1a2a9')
    def test_namespace_sg_svc_isolation(self):
        # Check security group resources are created
        ns1_name, ns1 = self.create_namespace()
        ns2_name, ns2 = self.create_namespace()

        existing_namespaces = [ns.metadata.name
                               for ns in self.list_namespaces().items]

        self.assertIn(ns1_name, existing_namespaces)
        self.assertIn(ns2_name, existing_namespaces)
        self.assertIn('default', existing_namespaces)

        subnet_ns1_name = 'ns/' + ns1_name + '-subnet'
        subnet_ns2_name = 'ns/' + ns2_name + '-subnet'
        net_crd_ns1_name = 'ns-' + ns1_name
        net_crd_ns2_name = 'ns-' + ns2_name

        net_crd_ns1 = self.get_kuryr_net_crds(net_crd_ns1_name)
        net_crd_ns2 = self.get_kuryr_net_crds(net_crd_ns2_name)

        self.assertIn(net_crd_ns1_name, net_crd_ns1['metadata']['name'])
        self.assertIn(net_crd_ns2_name, net_crd_ns2['metadata']['name'])

        seen_sgs = self.list_security_groups()
        seen_sg_ids = [sg['id'] for sg in seen_sgs]

        self.assertIn(net_crd_ns1['spec']['sgId'], seen_sg_ids)
        self.assertIn(net_crd_ns2['spec']['sgId'], seen_sg_ids)

        # Create pods and services in different namespaces
        pod_ns1_name, pod_ns1 = self.create_pod(labels={"app": 'pod-label'},
                                                namespace=ns1_name)
        svc_ns1_name, _ = self.create_service(
            pod_label=pod_ns1.metadata.labels, namespace=ns1_name)
        svc_ns1_ip = self.get_service_ip(service_name=svc_ns1_name,
                                         namespace=ns1_name)

        pod_ns2_name, pod_ns2 = self.create_pod(labels={"app": 'pod-label'},
                                                namespace=ns2_name)
        svc_ns2_name, _ = self.create_service(
            pod_label=pod_ns2.metadata.labels, namespace=ns2_name)
        svc_ns2_ip = self.get_service_ip(service_name=svc_ns2_name,
                                         namespace=ns2_name)

        # Wait for services to be ready
        self.wait_service_status(svc_ns1_ip,
                                 CONF.kuryr_kubernetes.lb_build_timeout)
        self.wait_service_status(svc_ns2_ip,
                                 CONF.kuryr_kubernetes.lb_build_timeout)

        pod_nsdefault_name, pod_nsdefault = self.create_pod(
            labels={"app": 'pod-label'}, namespace='default')
        self.addCleanup(self.delete_pod, pod_nsdefault_name)

        # Check namespace svc connectivity and isolation
        # check connectivity from NS1 pod to NS1 service
        cmd = ["/bin/sh", "-c", "curl {dst_ip}".format(
            dst_ip=svc_ns1_ip)]
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(pod_ns1_name, cmd, ns1_name))

        # check no connectivity from NS1 pod to NS2 service
        cmd = ["/bin/sh", "-c", "curl {dst_ip}".format(
            dst_ip=svc_ns2_ip)]
        self.assertNotIn(consts.POD_OUTPUT,
                         self.exec_command_in_pod(pod_ns1_name, cmd, ns1_name))

        # check connectivity from default pod to NS2 service
        cmd = ["/bin/sh", "-c", "curl {dst_ip}".format(
            dst_ip=svc_ns2_ip)]
        self.assertIn(consts.POD_OUTPUT,
                      self.exec_command_in_pod(pod_nsdefault_name, cmd))

        # Check resources are deleted
        self._delete_namespace_resources(ns1_name, net_crd_ns1,
                                         subnet_ns1_name)
        self._delete_namespace_resources(ns2_name, net_crd_ns2,
                                         subnet_ns2_name)

    @decorators.idempotent_id('bddd5441-1244-429d-a125-b53ddfb132a9')
    def test_host_to_namespace_connectivity(self):
        # Create namespace and pod and service in that namespace
        namespace_name, namespace = self.create_namespace()
        self.addCleanup(self.delete_namespace, namespace_name)
        # Check host to namespace pod and service connectivity
        pod_name, pod = self.create_pod(labels={"app": 'pod-label'},
                                        namespace=namespace_name)
        pod_ip = self.get_pod_ip(pod_name, namespace=namespace_name)
        svc_name, _ = self.create_service(pod_label=pod.metadata.labels,
                                          namespace=namespace_name)
        service_ip = self.get_service_ip(service_name=svc_name,
                                         namespace=namespace_name)
        self.wait_service_status(service_ip,
                                 CONF.kuryr_kubernetes.lb_build_timeout)
        # Check connectivity to pod and service in the namespace
        self.ping_ip_address(pod_ip)
        resp = requests.get("http://{dst_ip}".format(dst_ip=service_ip))
        self.assertEqual(resp.status_code, 200)

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
