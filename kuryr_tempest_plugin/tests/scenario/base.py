# Copyright 2017 Red Hat, Inc.
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

import time

from oslo_log import log as logging

import requests

import kubernetes
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.stream import stream

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BaseKuryrScenarioTest(manager.NetworkScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(BaseKuryrScenarioTest, cls).skip_checks()
        if not CONF.service_available.kuryr:
            raise cls.skipException('Kuryr support is required')

    @classmethod
    def setup_clients(cls):
        super(BaseKuryrScenarioTest, cls).setup_clients()
        cls.k8s_client = k8s_client

    @classmethod
    def resource_setup(cls):
        super(BaseKuryrScenarioTest, cls).resource_setup()
        cls.pod_fips = []
        # TODO(dmellado): Config k8s client in a cleaner way
        k8s_config.load_kube_config()

    @classmethod
    def resource_cleanup(cls):
        super(BaseKuryrScenarioTest, cls).resource_cleanup()
        for fip in cls.pod_fips:
            cls.os_admin.floating_ips_client.delete_floatingip(
                fip['floatingip']['id'])

    @classmethod
    def create_pod(cls, name=None, labels=None, image='kuryr/demo',
                   namespace="default"):
        if not name:
            name = data_utils.rand_name(prefix='kuryr-pod')
        pod = cls.k8s_client.V1Pod()
        pod.metadata = cls.k8s_client.V1ObjectMeta(name=name, labels=labels)

        container = cls.k8s_client.V1Container(name=name)
        container.image = image
        container.args = ["sleep", "3600"]

        spec = cls.k8s_client.V1PodSpec(containers=[container])

        pod.spec = spec
        cls.k8s_client.CoreV1Api().create_namespaced_pod(namespace=namespace,
                                                         body=pod)
        status = ""
        while status != "Running":
            # TODO(dmellado) add timeout config to tempest plugin
            time.sleep(1)
            status = cls.get_pod_status(name, namespace)

        return name, pod

    @classmethod
    def delete_pod(cls, pod_name, body=None, namespace="default"):
        if body is None:
            body = {}
        cls.k8s_client.CoreV1Api().delete_namespaced_pod(
            name=pod_name,
            body=body,
            namespace=namespace)

    @classmethod
    def get_pod_ip(cls, pod_name, namespace="default"):
        pod_list = cls.k8s_client.CoreV1Api().list_namespaced_pod(
            namespace=namespace)
        for pod in pod_list.items:
            if pod.metadata.name == pod_name:
                return pod.status.pod_ip

    @classmethod
    def get_pod_status(cls, pod_name, namespace="default"):
        pod_list = cls.k8s_client.CoreV1Api().list_namespaced_pod(
            namespace=namespace)
        for pod in pod_list.items:
            if pod.metadata.name == pod_name:
                return pod.status.phase

    def get_pod_port(self, pod_name, namespace="default"):
        # TODO(gcheresh) get pod port using container id, as kuryr this would
        # depend on port_debug kuryr feature
        full_port_name = str(namespace) + "/" + str(pod_name)
        port_list = self.os_admin.ports_client.list_ports()
        found_ports = []
        for port in port_list['ports']:
            if full_port_name == port['name']:
                return port
            if pod_name == port['name']:
                found_ports.append(port)
        # To maintain backwards compatibility with the old naming we also check
        # for matchings without namespace at the port name.
        # Note, if there is more than one port with the same name, we have no
        # way to differentiate them unless the namespace is used at the port
        # name, since kubernetes will avoid having pods with the same name
        # under the same namespace
        if len(found_ports) == 1:
            return found_ports[0]

    def exec_command_in_pod(self, pod_name, command, namespace="default"):
        api = self.k8s_client.CoreV1Api()
        return stream(api.connect_get_namespaced_pod_exec, pod_name, namespace,
                      command=command, stderr=False, stdin=False, stdout=True,
                      tty=False)

    def assign_fip_to_pod(self, pod_name, namespace="default"):
        ext_net_id = CONF.network.public_network_id
        pod_fip = self.os_admin.floating_ips_client.create_floatingip(
            floating_network_id=ext_net_id,
            tenant_id=self.get_project_id(),
            port_id=self.get_pod_port(pod_name)['id'])
        self.pod_fips.append(pod_fip)
        return pod_fip

    def get_project_id(self, project_name='k8s'):
        projects_list = self.os_admin.projects_client.list_projects()
        for project in projects_list['projects']:
            if project_name == project['name']:
                return project['id']

    @classmethod
    def create_service(cls, pod_label, service_name=None, api_version="v1",
                       kind=None, protocol="TCP", port=80, target_port=8080,
                       spec_type='ClusterIP', namespace="default"):
        if not service_name:
            service_name = data_utils.rand_name(prefix='kuryr-service')
        service = cls.k8s_client.V1Service()
        service.api_version = api_version
        service.kind = kind
        service.metadata = cls.k8s_client.V1ObjectMeta(name=service_name)

        spec = cls.k8s_client.V1ServiceSpec()
        spec.ports = [cls.k8s_client.V1ServicePort(
            protocol=protocol,
            port=port,
            target_port=target_port)]
        spec.selector = pod_label
        spec.type = spec_type

        service.spec = spec
        service_obj = cls.k8s_client.CoreV1Api().create_namespaced_service(
            namespace=namespace, body=service)
        return service_name, service_obj

    @classmethod
    def delete_service(cls, service_name, namespace="default"):
        # FIXME(dulek): This is needed to support tempest plugin on
        #               stable/queens as kubernetes package is constrainted to
        #               4.0.0 there and it doesn't accept ``body`` parameter.
        #               Remove this once stable/queens becomes unsupported.
        if kubernetes.__version__ == '4.0.0':
            cls.k8s_client.CoreV1Api().delete_namespaced_service(
                name=service_name,
                namespace=namespace)
        else:
            delete_options = cls.k8s_client.V1DeleteOptions()
            cls.k8s_client.CoreV1Api().delete_namespaced_service(
                name=service_name,
                namespace=namespace,
                body=delete_options)

    @classmethod
    def get_service_ip(
            cls, service_name, spec_type="ClusterIP", namespace="default"):
        api = cls.k8s_client.CoreV1Api()
        while True:
            time.sleep(5)
            service = api.read_namespaced_service(service_name, namespace)
            if spec_type == "LoadBalancer":
                if service.status.load_balancer.ingress:
                    return service.status.load_balancer.ingress[0].ip
            elif spec_type == "ClusterIP":
                return service.spec.cluster_ip
            else:
                raise lib_exc.NotImplemented()

    @classmethod
    def wait_service_status(cls, service_ip, timeout_period):
        session = requests.Session()
        start = time.time()
        while time.time() - start < timeout_period:
            try:
                time.sleep(5)
                session.get("http://{0}".format(service_ip), timeout=2)
                return
            except Exception:
                LOG.warning('No initial traffic is passing through.')
                time.sleep(5)
        LOG.error(
            "Traffic didn't pass within the period of %s" % timeout_period)
        raise lib_exc.ServerFault()

    @classmethod
    def create_setup_for_service_test(cls, pod_num=2):
        for i in range(pod_num):
            pod_name, pod = cls.create_pod(
                labels={"app": 'pod-label'}, image='celebdor/kuryr-demo')
            cls.addClassResourceCleanup(cls.delete_pod, pod_name)
        service_name, service_obj = cls.create_service(
            pod_label=pod.metadata.labels)
        cls.service_ip = cls.get_service_ip(service_name)
        cls.wait_service_status(
            cls.service_ip, CONF.kuryr_kubernetes.lb_build_timeout)

        cls.addClassResourceCleanup(cls.delete_service, service_name)
