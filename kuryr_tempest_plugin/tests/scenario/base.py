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
import json
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

KURYR_NET_CRD_GROUP = 'openstack.org'
KURYR_NET_CRD_VERSION = 'v1'
KURYR_NET_CRD_PLURAL = 'kuryrnets'
K8S_ANNOTATION_PREFIX = 'openstack.org/kuryr'
K8S_ANNOTATION_LBAAS_STATE = K8S_ANNOTATION_PREFIX + '-lbaas-state'


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
        pod = self.k8s_client.CoreV1Api().read_namespaced_pod_status(
            namespace=namespace, name=pod_name)
        kuryr_if = json.loads(pod.metadata.annotations[
            'openstack.org/kuryr-vif'])

        # FIXME(dulek): We need this compatibility code to run stable/queens.
        #               Remove this once it's no longer supported.
        if 'eth0' in kuryr_if:
            kuryr_if = kuryr_if['eth0']
        elif kuryr_if.get('versioned_object.name') == 'PodState':
            kuryr_if = kuryr_if['versioned_object.data']['default_vif']

        return kuryr_if['versioned_object.data']['id']

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
            port_id=self.get_pod_port(pod_name, namespace))
        self.pod_fips.append(pod_fip)
        return pod_fip

    def get_project_id(self):
        project_name = CONF.kuryr_kubernetes.kubernetes_project_name
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
                # NOTE(yboaron): In some cases, OpenShift may overwrite
                # LB's IP stored at service.status, we need to make sure that
                # this function will return the IP that was annotated by
                # Kuryr controller
                if service.status.load_balancer.ingress:
                    endpoints = api.read_namespaced_endpoints(
                        service_name, namespace)
                    annotations = endpoints.metadata.annotations
                    try:
                        ann_dict = json.loads(
                            annotations[K8S_ANNOTATION_LBAAS_STATE])
                        ann_lb_ip = (
                            ann_dict["versioned_object.data"]
                            ["service_pub_ip_info"]
                            ["versioned_object.data"]
                            ["ip_addr"])
                    except KeyError:
                        LOG.info("Waiting till LB's IP appears in annotation "
                                 "(ingress.ip=%s)",
                                 service.status.load_balancer.ingress[0].ip)
                        continue
                    if ann_lb_ip != service.status.load_balancer.ingress[0].ip:
                        LOG.warning(
                            'Annotated pub_ip(%s) != ingress.ip(%s).',
                            ann_lb_ip,
                            service.status.load_balancer.ingress[0].ip)
                        return ann_lb_ip
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
    def create_setup_for_service_test(cls, pod_num=2, spec_type="ClusterIP",
                                      label=None, namespace="default",
                                      get_ip=True):
        label = label or data_utils.rand_name('kuryr-app')
        for i in range(pod_num):
            pod_name, pod = cls.create_pod(
                labels={"app": label}, namespace=namespace)
            cls.addClassResourceCleanup(cls.delete_pod, pod_name,
                                        namespace=namespace)
        service_name, service_obj = cls.create_service(
            pod_label=pod.metadata.labels, spec_type=spec_type,
            namespace=namespace)
        if get_ip:
            cls.service_ip = cls.get_service_ip(
                service_name, spec_type=spec_type, namespace=namespace)
            cls.verify_lbaas_endpoints_configured(service_name)
            cls.wait_service_status(
                cls.service_ip, CONF.kuryr_kubernetes.lb_build_timeout)

        cls.addClassResourceCleanup(cls.delete_service, service_name,
                                    namespace=namespace)

    @classmethod
    def create_namespace(cls, name=None):
        if not name:
            name = data_utils.rand_name(prefix='kuryr-namespace')
        kuryr_crd_annotation = K8S_ANNOTATION_PREFIX + "-net-crd"

        namespace = cls.k8s_client.V1Namespace()
        namespace.metadata = cls.k8s_client.V1ObjectMeta(name=name)
        namespace_obj = cls.k8s_client.CoreV1Api().create_namespace(
            body=namespace)

        # wait until namespace gets created
        while True:
            time.sleep(1)
            ns = cls.k8s_client.CoreV1Api().read_namespace_status(name)
            if (ns.metadata.annotations and
                    ns.metadata.annotations.get(kuryr_crd_annotation)):
                break

        return name, namespace_obj

    @classmethod
    def delete_namespace(cls, name, **kwargs):
        body = cls.k8s_client.V1DeleteOptions(**kwargs)
        cls.k8s_client.CoreV1Api().delete_namespace(name=name, body=body)

    @classmethod
    def list_namespaces(cls, **kwargs):
        return cls.k8s_client.CoreV1Api().list_namespace(**kwargs)

    @classmethod
    def get_kuryr_net_crds(cls, name):
        return cls.k8s_client.CustomObjectsApi().get_cluster_custom_object(
            group=KURYR_NET_CRD_GROUP, version=KURYR_NET_CRD_VERSION,
            plural=KURYR_NET_CRD_PLURAL, name=name)

    def get_pod_name_list(self, namespace="default"):
        return [pod.metadata.name for pod in
                self.k8s_client.CoreV1Api().list_namespaced_pod(
                    namespace=namespace).items]

    def _run_and_assert_fn(self, fn, repeats=10, responses_num=2):
        cmd_outputs = set()
        for i in range(repeats):
            cmd_outputs.add(fn())
        self.assertEqual(responses_num, len(cmd_outputs),
                         'Number of exclusive responses is incorrect. '
                         'Got %s.' % cmd_outputs)

    @classmethod
    def verify_lbaas_endpoints_configured(cls, ep_name, namespace='default'):
        cls._verify_endpoints_annotation(
            ep_name=ep_name, ann_string=K8S_ANNOTATION_LBAAS_STATE,
            poll_interval=10)

    @classmethod
    def _verify_endpoints_annotation(cls, ep_name, ann_string,
                                     poll_interval=1, namespace='default'):
        # wait until endpoint annotation created
        while True:
            time.sleep(poll_interval)
            ep = cls.k8s_client.CoreV1Api().read_namespaced_endpoints(
                ep_name, namespace)
            annotations = ep.metadata.annotations
            try:
                json.loads(annotations[ann_string])
                return
            except KeyError:
                LOG.info("Waiting till %s will appears "
                         "in ep=%s annotation ", ann_string, ep_name)
                continue

    def create_vm_for_connectivity_test(self):
        keypair = self.create_keypair()
        sec_grp = self._create_security_group()
        security_groups = [
            {'name': sec_grp['name']}
        ]
        server = self.create_server(name=data_utils.rand_name(prefix='kuryr'),
                                    key_name=keypair['name'],
                                    security_groups=security_groups)
        fip = self.create_floating_ip(server)
        ssh_client = self.get_remote_client(fip['floating_ip_address'],
                                            private_key=keypair['private_key'])
        return ssh_client, fip

    def check_controller_pod_status_for_time_period(self, retry_attempts=20,
                                                    time_between_attempts=5,
                                                    status='Running'):
        # Check that the controller pod status doesn't change from provided
        # status parameter, so for example it should stay in Running state when
        # the service with incorrect parameters was created

        controller_pods = [
            pod.metadata.name for pod in
            self.k8s_client.CoreV1Api().list_namespaced_pod(
                namespace=CONF.kuryr_kubernetes.kube_system_namespace).items
            if pod.metadata.name.startswith('kuryr-controller')]

        while retry_attempts != 0:
            time.sleep(time_between_attempts)
            for controller_pod in controller_pods:
                self.assertEqual("Running", self.get_pod_status(
                    controller_pod,
                    CONF.kuryr_kubernetes.kube_system_namespace),
                    'Kuryr controller is not in the %s state' % status
                )
            retry_attempts -= 1
