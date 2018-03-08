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

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.stream import stream

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.scenario import manager

CONF = config.CONF


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

    def create_pod(self, name=None, image='kuryr/demo',
                   namespace="default"):
        name = data_utils.rand_name(prefix='kuryr-pod')
        pod = self.k8s_client.V1Pod()
        pod.metadata = self.k8s_client.V1ObjectMeta(name=name)

        container = self.k8s_client.V1Container(name=name)
        container.image = image
        container.args = ["sleep", "3600"]

        spec = self.k8s_client.V1PodSpec(containers=[container])

        pod.spec = spec
        self.k8s_client.CoreV1Api().create_namespaced_pod(namespace=namespace,
                                                          body=pod)
        status = ""
        while status != "Running":
            # TODO(dmellado) add timeout config to tempest plugin
            time.sleep(1)
            status = self.get_pod_status(name, namespace)

        return name, pod

    def delete_pod(self, pod_name, body=None, namespace="default"):
        if body is None:
            body = {}
        self.k8s_client.CoreV1Api().delete_namespaced_pod(
            name=pod_name,
            body=body,
            namespace=namespace)

    def get_pod_ip(self, pod_name, namespace="default"):
        pod_list = self.k8s_client.CoreV1Api().list_namespaced_pod(
            namespace=namespace)
        for pod in pod_list.items:
            if pod.metadata.name == pod_name:
                return pod.status.pod_ip

    def get_pod_status(self, pod_name, namespace="default"):
        pod_list = self.k8s_client.CoreV1Api().list_namespaced_pod(
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
