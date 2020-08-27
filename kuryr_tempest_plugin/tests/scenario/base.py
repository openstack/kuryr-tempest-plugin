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
import six.moves

from functools import partial
import ipaddress
import json
import six
import socket
import time

from oslo_log import log as logging

import requests

import kubernetes
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.stream import stream
from kuryr_tempest_plugin.tests.scenario import consts

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager

CONF = config.CONF
LOG = logging.getLogger(__name__)

KURYR_CRD_GROUP = 'openstack.org'
KURYR_CRD_VERSION = 'v1'
KURYR_NET_CRD_PLURAL = 'kuryrnets'
KURYR_NETWORK_CRD_PLURAL = 'kuryrnetworks'
KURYR_PORT_CRD_PLURAL = 'kuryrports'
KURYR_LOAD_BALANCER_CRD_PLURAL = 'kuryrloadbalancers'
K8S_ANNOTATION_PREFIX = 'openstack.org/kuryr'
K8S_ANNOTATION_LBAAS_STATE = K8S_ANNOTATION_PREFIX + '-lbaas-state'
K8S_ANNOTATION_LBAAS_RT_STATE = K8S_ANNOTATION_PREFIX + '-lbaas-route-state'
KURYR_ROUTE_DEL_VERIFY_TIMEOUT = 30
KURYR_CONTROLLER = 'kuryr-controller'
OS_ROUTES_API = 'route.openshift.io'
OS_ROUTES_VERSION = 'v1'
OS_ROUTES_PLURAL = "routes"


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
        cls.namespaces = []
        # TODO(dmellado): Config k8s client in a cleaner way
        k8s_config.load_kube_config()

    @classmethod
    def resource_cleanup(cls):
        super(BaseKuryrScenarioTest, cls).resource_cleanup()
        for fip in cls.pod_fips:
            cls.os_admin.floating_ips_client.delete_floatingip(
                fip['floatingip']['id'])
        for namespace in cls.namespaces:
            cls.delete_namespace(namespace)

    @classmethod
    def create_network_policy(cls, name=None, namespace='default',
                              match_labels=None, match_expressions=None,
                              ingress_port=None, ingress_port_protocol='TCP',
                              ingress_ipblock_cidr=None,
                              ingress_ipblock_except=[],
                              egress_port=None, egress_port_protocol='TCP',
                              egress_ipblock_cidr=None,
                              egress_ipblock_except=[]):
        if not name:
            name = data_utils.rand_name(prefix='kuryr-network-policy')
        np = k8s_client.V1NetworkPolicy()
        np.kind = 'NetworkPolicy'
        np.api_version = 'networking.k8s.io/v1'
        np.metadata = k8s_client.V1ObjectMeta(name=name,
                                              namespace=namespace)
        to, _from = None, None
        if egress_ipblock_cidr:
            to = [k8s_client.V1NetworkPolicyPeer(
                ip_block=k8s_client.V1IPBlock(cidr=egress_ipblock_cidr,
                                              _except=egress_ipblock_except))]
        if ingress_ipblock_cidr:
            _from = [k8s_client.V1NetworkPolicyPeer(
                ip_block=k8s_client.V1IPBlock(cidr=ingress_ipblock_cidr,
                                              _except=ingress_ipblock_except))]
        if ingress_port:
            ingress_port = [k8s_client.V1NetworkPolicyPort(
                port=ingress_port, protocol=ingress_port_protocol)]
        if egress_port:
            egress_port = [k8s_client.V1NetworkPolicyPort(
                port=egress_port, protocol=egress_port_protocol)]

        np.spec = k8s_client.V1NetworkPolicySpec(
            egress=[k8s_client.V1NetworkPolicyEgressRule(
                ports=egress_port,
                to=to)],
            ingress=[k8s_client.V1NetworkPolicyIngressRule(
                ports=ingress_port,
                _from=_from)],
            pod_selector=k8s_client.V1LabelSelector(
                match_expressions=match_expressions,
                match_labels=match_labels),
            policy_types=['Ingress', 'Egress'])

        return k8s_client.NetworkingV1Api(
        ).create_namespaced_network_policy(namespace=namespace, body=np)

    @classmethod
    def list_security_group_rules(cls, security_group_id):
        rules = cls.os_admin.security_groups_client.show_security_group(
            security_group_id)['security_group']['security_group_rules']
        return rules

    @classmethod
    def update_network_policy(cls, np):
        np_name = np.metadata.name
        np_namespace = np.metadata.namespace
        np_updated = cls.k8s_client.NetworkingV1Api(
            ).replace_namespaced_network_policy(
                name=np_name, namespace=np_namespace, body=np)
        return np_updated

    @classmethod
    def read_network_policy(cls, np):
        np_name = np.metadata.name
        np_namespace = np.metadata.namespace
        return cls.k8s_client.NetworkingV1Api(
            ).read_namespaced_network_policy(
                name=np_name, namespace=np_namespace)

    @classmethod
    def create_pod(cls, name=None, labels=None, image='kuryr/demo',
                   namespace="default", annotations=None, wait_for_status=True,
                   affinity=None):
        if not name:
            name = data_utils.rand_name(prefix='kuryr-pod')
        pod = cls.k8s_client.V1Pod()
        pod.metadata = cls.k8s_client.V1ObjectMeta(name=name, labels=labels,
                                                   annotations=annotations)

        container = kubernetes.client.V1Container(
            name=name, image=image, image_pull_policy='IfNotPresent')

        spec = cls.k8s_client.V1PodSpec(containers=[container])

        pod.spec = spec
        pod.spec.affinity = affinity
        cls.k8s_client.CoreV1Api().create_namespaced_pod(namespace=namespace,
                                                         body=pod)
        if wait_for_status:
            cls.wait_for_pod_status(
                name,
                namespace=namespace,
                pod_status='Running',
                retries=consts.POD_STATUS_RETRIES)

        return name, pod

    @classmethod
    def delete_network_policy(cls, name, namespace='default'):
        body = cls.k8s_client.V1DeleteOptions()
        cls.k8s_client.NetworkingV1Api().delete_namespaced_network_policy(
            name=name,
            namespace=namespace,
            body=body)

    @classmethod
    def delete_pod(cls, pod_name, body=None, namespace="default"):
        if body is None:
            body = {}
        cls.k8s_client.CoreV1Api().delete_namespaced_pod(
            name=pod_name,
            body=body,
            namespace=namespace)
        # TODO(apuimedo) This sleep to be replaced with a polling with
        # timeout for the pod object to be gone from k8s api.
        time.sleep(30)

    @classmethod
    def wait_for_pod_status(cls, pod_name, namespace="default",
                            pod_status=None, retries=30):
        while pod_status != cls.get_pod_status(
                pod_name,
                namespace=namespace):
            time.sleep(1)
            retries -= 1
            if retries == 0:
                raise lib_exc.TimeoutException()

    @classmethod
    def get_pod_ip(cls, pod_name, namespace="default"):
        try:
            pod = cls.k8s_client.CoreV1Api().read_namespaced_pod(pod_name,
                                                                 namespace)
            return pod.status.pod_ip
        except kubernetes.client.rest.ApiException:
            return None

    @classmethod
    def get_host_ip_for_pod(cls, pod_name, namespace="default"):
        try:
            pod = cls.k8s_client.CoreV1Api().read_namespaced_pod(pod_name,
                                                                 namespace)
            return pod.status.host_ip
        except kubernetes.client.rest.ApiException:
            return None

    @classmethod
    def get_pod_status(cls, pod_name, namespace="default"):
        try:
            pod = cls.k8s_client.CoreV1Api().read_namespaced_pod(pod_name,
                                                                 namespace)
            return pod.status.phase
        except kubernetes.client.rest.ApiException:
            return None

    @classmethod
    def get_readiness_state(cls, pod_name, namespace="default",
                            container_name=None):
        try:
            pod = cls.k8s_client.CoreV1Api().read_namespaced_pod(pod_name,
                                                                 namespace)
        except kubernetes.client.rest.ApiException:
            return None

        if container_name:
            for container in pod.status.container_statuses:
                if container.name == container_name:
                    return container.ready
        else:
            for condition in pod.status.conditions:
                if condition.type == 'Ready':
                    return condition.status

    @classmethod
    def get_pod_readiness(cls, pod_name, namespace="default",
                          container_name=None):
        LOG.info("Checking if pod {} is ready".format(pod_name))
        return cls.get_readiness_state(pod_name, namespace=namespace,
                                       container_name=container_name)

    @classmethod
    def get_container_readiness(cls, pod_name, namespace="default",
                                container_name=None):
        return cls.get_readiness_state(pod_name, namespace=namespace,
                                       container_name=container_name)

    def get_pod_port(self, pod_name, namespace="default"):
        try:
            # TODO(gryf): Current approach is to look at the KuryrPort CRD,
            # and if it doesn't exists, fallback to check the pod annotations
            crd = (self.k8s_client.CustomObjectsApi()
                   .get_namespaced_custom_object(group=KURYR_CRD_GROUP,
                                                 version=KURYR_CRD_VERSION,
                                                 namespace=namespace,
                                                 plural=KURYR_PORT_CRD_PLURAL,
                                                 name=pod_name))
            try:
                vif = [v['vif'].get('versioned_object.data', {}).get('id')
                       for k, v in crd['status']['vifs'].items()
                       if v.get('default')]
            except KeyError:
                # TODO(gryf): Remove this after moving vifs to status succeed.
                vif = [v['vif'].get('versioned_object.data', {}).get('id')
                       for k, v in crd['spec']['vifs'].items()
                       if v.get('default')]

            if vif and vif[0]:
                return vif[0]
            else:
                return None
        except kubernetes.client.rest.ApiException:
            pod = self.k8s_client.CoreV1Api().read_namespaced_pod_status(
                namespace=namespace, name=pod_name)
            kuryr_if = json.loads(pod.metadata.annotations[
                'openstack.org/kuryr-vif'])

            # FIXME(dulek): We need this compatibility code to run
            #               stable/queens. Remove this once it's no longer
            #               supported.
            if 'eth0' in kuryr_if:
                kuryr_if = kuryr_if['eth0']
            elif kuryr_if.get('versioned_object.name') == 'PodState':
                kuryr_if = kuryr_if['versioned_object.data']['default_vif']

            return kuryr_if['versioned_object.data']['id']

    @classmethod
    def get_pod_node_name(cls, pod_name, namespace="default"):
        pod_list = cls.k8s_client.CoreV1Api().list_namespaced_pod(
            namespace=namespace, field_selector='metadata.name=%s' % pod_name)
        if not pod_list.items:
            return None
        else:
            return pod_list.items[0].spec.node_name

    def exec_command_in_pod(self, pod_name, command, namespace="default",
                            stderr=False, container=None,
                            req_timeout=10, f_timeout=2):
        api = self.k8s_client.CoreV1Api()
        kwargs = dict(command=command, stdin=False, stdout=True, tty=False,
                      stderr=stderr)
        if container is not None:
            kwargs['container'] = container

        for attempt in range(1, 6):
            try:
                # NOTE(yboaron): sometimes the
                # 'connect_get_namespaced_pod_exec'and rest of functions
                # from [1] that takes timeout as parameter are hanging for some
                # reason (on OS select) although the command completed. To
                # resolve that we set the '_request_timeout' for
                # 'connect_get_namespaced_pod_exec' and f_timeout for the rest
                # of functions.
                # [1] https://github.com/kubernetes-client/python-base/blob/
                # master/stream/ws_client.py
                if req_timeout is not None:
                    kwargs['_request_timeout'] = req_timeout
                if stderr:
                    kwargs['_preload_content'] = False
                    resp = stream(api.connect_get_namespaced_pod_exec,
                                  pod_name, namespace, **kwargs)
                    # Run until completion
                    resp.run_forever(timeout=f_timeout)
                    return (resp.read_stdout(timeout=f_timeout),
                            resp.read_stderr(timeout=f_timeout))
                else:
                    return stream(api.connect_get_namespaced_pod_exec,
                                  pod_name, namespace, **kwargs)
            except kubernetes.client.rest.ApiException:
                LOG.exception("Error received when contacting K8s API, "
                              "attempt %d/5", attempt)

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
        service = api.read_namespaced_service(service_name, namespace)
        if spec_type == "LoadBalancer":
            # In case of a cloud provider not being configured, OpenShift
            # allocates an external IP and overwrites the service
            # status/ingress/IP set by Kuryr-controller.
            # In this case, we should retrieve the external IP from
            # Kuryr's annotation.
            if CONF.kuryr_kubernetes.kuryrloadbalancers:
                return cls.get_svc_ip_on_crd(service_name, namespace)
            else:
                return cls.get_svc_ip_on_annotation(service_name, namespace)
        elif spec_type == "ClusterIP":
            return service.spec.cluster_ip
        else:
            raise lib_exc.NotImplemented()

    @classmethod
    def get_svc_ip_on_annotation(cls, service_name, namespace):
        api = cls.k8s_client.CoreV1Api()
        start = time.time()
        while time.time() - start < consts.LB_TIMEOUT:
            time.sleep(5)
            service = api.read_namespaced_service(service_name, namespace)
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
                    if not CONF.kuryr_kubernetes.cloud_provider:
                        return ann_lb_ip
                return service.status.load_balancer.ingress[0].ip
        msg = "Timed out waiting for endpoints annotation %s" % service_name
        raise lib_exc.TimeoutException(msg)

    @classmethod
    def get_svc_ip_on_crd(cls, service_name, namespace):
        api = cls.k8s_client.CoreV1Api()
        start = time.time()
        while time.time() - start < consts.LB_TIMEOUT:
            time.sleep(5)
            service = api.read_namespaced_service(service_name, namespace)
            if service.status.load_balancer.ingress:
                try:
                    klb_crd = cls.get_kuryr_loadbalancer_crds(
                        service_name, namespace)
                except kubernetes.client.rest.ApiException:
                    continue
                ingress_ip = service.status.load_balancer.ingress[0].ip
                klb_status = klb_crd.get('status')
                if (klb_status and klb_status.get('service_pub_ip_info')):
                    try:
                        crd_lb_ip = klb_status['service_pub_ip_info'][
                            'ip_addr']
                    except KeyError:
                        LOG.info("Waiting till LB's IP appears in CRD "
                                 "(ingress.ip=%s)", ingress_ip)
                        continue
                if crd_lb_ip != ingress_ip:
                    LOG.warning(
                        'LB CRD pub_ip(%s) != ingress.ip(%s).',
                        crd_lb_ip, ingress_ip)
                    if not CONF.kuryr_kubernetes.cloud_provider:
                        return crd_lb_ip
                return ingress_ip
        msg = "Timed out waiting for lb crd status %s" % service_name
        raise lib_exc.TimeoutException(msg)

    @classmethod
    def wait_kuryr_annotation(cls, group, version, plural, annotation,
                              timeout_period, name, namespace='default'):
        coa_client = cls.k8s_client.CustomObjectsApi()
        start = time.time()
        while time.time() - start < timeout_period:
            time.sleep(1)
            resource = coa_client.get_namespaced_custom_object(
                group, version, namespace, plural, name)
            if resource['metadata'].get('annotations') is None:
                continue
            for resp_annotation in resource['metadata']['annotations']:
                if annotation in resp_annotation:
                    return
            LOG.info("Waiting till %s will appear "
                     "in %s/%s annotation ", annotation, plural, name)
        raise lib_exc.ServerFault()

    @classmethod
    def _verify_connectivity(cls, dest_ip, timeout_period, protocol, port,
                             expected_different_replies=1):

        def verify_tcp(dest_ip, port, session):
            addr = ipaddress.ip_address(six.text_type(dest_ip))
            if addr.version == 6:
                dest_ip = '[%s]' % dest_ip
            try:
                resp = requests.get("http://{0}:{1}".format(dest_ip, port),
                                    timeout=2)
                if resp.status_code == requests.codes.OK:
                    return resp
            except Exception:
                return None
            return None

        def verify_udp(dest_ip, port):
            udp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client_sock.settimeout(5.0)
            udp_client_sock.sendto("Hi Server, howRU?".encode(),
                                   (dest_ip, port))
            try:
                data, addr = udp_client_sock.recvfrom(1024)
            except socket.timeout:
                return None
            return data

        if protocol == "TCP":
            session = requests.Session()
            iter_func = partial(verify_tcp, session=session)
        elif protocol == "UDP":
            iter_func = verify_udp
        else:
            LOG.warning("Unsupported protocol %s, returning", protocol)
            return False

        start = time.time()
        unique_resps = set()
        while time.time() - start < timeout_period:
            time.sleep(5)
            unique_resps.add(iter_func(dest_ip, port))
            unique_resps.discard(None)
            if len(unique_resps) == expected_different_replies:
                LOG.info('We received %d replies from prot=%s;%s:%d - '
                         'connectivity was veified!',
                         expected_different_replies, protocol, dest_ip, port)
                return True
            LOG.info('Connectivity not verified yet, we received so far %d '
                     'replies from prot=%s;%s:%d', len(unique_resps),
                     protocol, dest_ip, port)
        LOG.error("Can't connect to %s:%d", dest_ip, port)
        return False

    @classmethod
    def wait_service_status(cls, service_ip, timeout_period, protocol="TCP",
                            port=80, num_of_back_ends=1):
        if cls._verify_connectivity(
                service_ip, timeout_period, protocol, port,
                expected_different_replies=num_of_back_ends):
            LOG.info('Service responding...')
        else:
            LOG.error("Can't connect service's IP %s", service_ip)
            raise lib_exc.ServerFault()

    @classmethod
    def wait_ep_members_status(cls, ep_name, namespace, timeout_period):
        num_of_be = 0
        ep = cls.k8s_client.CoreV1Api().read_namespaced_endpoints(
            ep_name, namespace)
        try:
            subset = ep.subsets[0]
            subset_ports = subset.ports[0]
            for subset_address in subset.addresses:
                LOG.info('Verifying connectivity for EP backend: %s:%d; '
                         'prot=%s', subset_address.ip, subset_ports.port,
                         subset_ports.protocol)
                if cls._verify_connectivity(subset_address.ip, timeout_period,
                                            subset_ports.protocol,
                                            subset_ports.port):
                    num_of_be += 1
                    LOG.info('EP member %s responding...', subset_address.ip)
                else:
                    LOG.error("Can't connect to EP member %s",
                              subset_address.ip)
                    raise lib_exc.ServerFault()
        except Exception:
            LOG.error("wait_ep_members_status: failed to retrieve "
                      "members details EP=%s", ep)
            return 0
        return num_of_be

    @classmethod
    def create_setup_for_service_test(cls, pod_num=2, spec_type="ClusterIP",
                                      protocol="TCP", port=80,
                                      target_port=8080, label=None,
                                      namespace="default", get_ip=True,
                                      service_name=None, cleanup=True):

        label = label or data_utils.rand_name('kuryr-app')
        for i in range(pod_num):
            pod_name, pod = cls.create_pod(
                labels={"app": label}, namespace=namespace)
            if cleanup:
                cls.addClassResourceCleanup(cls.delete_pod, pod_name,
                                            namespace=namespace)
        cls.pod_num = pod_num
        service_name, service_obj = cls.create_service(
            pod_label=pod.metadata.labels, spec_type=spec_type,
            protocol=protocol, port=port, target_port=target_port,
            namespace=namespace, service_name=service_name)
        if get_ip:
            cls.service_ip = cls.get_service_ip(
                service_name, spec_type=spec_type, namespace=namespace)
            # This is already waiting for endpoint annotations to be made by
            # Kuryr
            cls.verify_lbaas_endpoints_configured(service_name, pod_num,
                                                  namespace)
            cls.service_name = service_name
        if cleanup:
            cls.addClassResourceCleanup(cls.delete_service, service_name,
                                        namespace=namespace)

    @classmethod
    def create_namespace(cls, name=None, wait_for_crd=True,
                         timeout_period=consts.NS_TIMEOUT):
        if not name:
            name = data_utils.rand_name(prefix='kuryr-namespace')
        namespace = cls.k8s_client.V1Namespace()
        namespace.metadata = cls.k8s_client.V1ObjectMeta(name=name)
        namespace_obj = cls.k8s_client.CoreV1Api().create_namespace(
            body=namespace)

        if not wait_for_crd:
            return name, namespace_obj

        start = time.time()
        if CONF.kuryr_kubernetes.kuryrnetworks:
            # wait until kuryrnetwork CRD gets populated
            while time.time() - start < timeout_period:
                time.sleep(5)
                try:
                    kns_crd = cls.get_kuryr_network_crds(name)
                except kubernetes.client.rest.ApiException:
                    continue
                if (kns_crd.get('status') and
                        kns_crd['status'].get('routerId')):
                    break
            if (not kns_crd.get('status')) or (
                    not kns_crd.get('status').get('routerId')):
                msg = 'Timed out waiting for kns crd %s creation' % name
                raise lib_exc.TimeoutException(msg)
        else:
            kuryr_crd_annotation = K8S_ANNOTATION_PREFIX + "-net-crd"
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
        try:
            cls.k8s_client.CoreV1Api().delete_namespace(name=name, body=body)
        except kubernetes.client.rest.ApiException as e:
            if e.status == 404:
                return
            raise

    @classmethod
    def get_namespace(cls, name):
        cls.k8s_client.CoreV1Api().read_namespace(name=name)

    @classmethod
    def list_namespaces(cls, **kwargs):
        return cls.k8s_client.CoreV1Api().list_namespace(**kwargs)

    @classmethod
    def list_network_policies(cls, namespace='default', **kwargs):
        network_policies_names = []
        k8s = cls.k8s_client.NetworkingV1Api()
        for np in k8s.list_namespaced_network_policy(namespace,
                                                     **kwargs).items:
            network_policies_names.append(np.metadata.name)
        return network_policies_names

    @classmethod
    def list_security_groups(cls, **filters):
        sgs = cls.os_admin.security_groups_client.list_security_groups(
            **filters)['security_groups']
        return sgs

    @classmethod
    def get_kuryr_net_crds(cls, name):
        return cls.k8s_client.CustomObjectsApi().get_cluster_custom_object(
            group=KURYR_CRD_GROUP, version=KURYR_CRD_VERSION,
            plural=KURYR_NET_CRD_PLURAL, name=name)

    @classmethod
    def get_kuryr_network_crds(cls, namespace):
        return cls.k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            group=KURYR_CRD_GROUP, version=KURYR_CRD_VERSION,
            namespace=namespace, plural=KURYR_NETWORK_CRD_PLURAL,
            name=namespace)

    @classmethod
    def get_kuryr_loadbalancer_crds(cls, name, namespace):
        return cls.k8s_client.CustomObjectsApi().get_namespaced_custom_object(
            group=KURYR_CRD_GROUP, version=KURYR_CRD_VERSION,
            namespace=namespace, plural=KURYR_LOAD_BALANCER_CRD_PLURAL,
            name=name)

    def get_pod_list(self, namespace='default', label_selector=''):
        return self.k8s_client.CoreV1Api().list_namespaced_pod(
            namespace=namespace, label_selector=label_selector).items

    def get_pod_name_list(self, namespace='default', label_selector=''):
        return [pod.metadata.name for pod in self.get_pod_list(
            namespace=namespace, label_selector=label_selector)]

    def get_controller_pod_names(self):
        controller_label = CONF.kuryr_kubernetes.controller_label
        controller_pod_names = self.get_pod_name_list(
            namespace=CONF.kuryr_kubernetes.kube_system_namespace,
            label_selector=controller_label)
        self.assertNotEmpty(controller_pod_names, "Can't find controller pods "
                            "with label %s" % controller_label)
        return controller_pod_names

    def _run_and_assert_fn(self, fn, repeats=10, responses_num=2):
        cmd_outputs = set()
        for i in range(repeats):
            cmd_outputs.add(fn())
        self.assertEqual(responses_num, len(cmd_outputs),
                         'Number of exclusive responses is incorrect. '
                         'Got %s.' % cmd_outputs)

    def assert_backend_amount(self, server_ip, amount, server_port=None,
                              protocol="TCP", headers=None):
        def req_tcp():
            resp = requests.get(url, headers=headers)
            self.assertEqual(requests.codes.OK, resp.status_code,
                             'Non-successful request to {}'.format(url))
            return resp

        def req_udp():
            # FIXME(yboaron): Current Octavia implementation doesn't
            # round-robin UDP pool as expected, to work-around that
            # a new socket (new local UDP port) is allocated per request.
            udp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client_sock.settimeout(3.0)
            udp_client_sock.sendto("Hi Server, howRU?".encode(),
                                   (server_ip, server_port))
            try:
                data, addr = udp_client_sock.recvfrom(1024)
            except Exception:
                # NOTE(yboaron): for UDP (unlike TCP) not getting reply from
                # the server is a valid use case.
                return None
            return data

        def pred(tester, responses):
            if protocol == 'TCP':
                unique_resps = set(resp.content for resp in responses)
            else:
                unique_resps = set(resp for resp in responses if resp
                                   is not None)
            tester.assertEqual(amount, len(unique_resps),
                               'Incorrect amount of unique backends. '
                               'Got {}'.format(unique_resps))

        if protocol == 'TCP':
            url = 'http://{}'.format(server_ip)
            req = req_tcp
        elif protocol == "UDP":
            self.assertIsNotNone(server_port, "server_port must be "
                                              "provided for UDP protocol")
            req = req_udp
        else:
            LOG.info("Unsupported protocol %s, returning", protocol)
            return

        self._run_and_assert(req, pred)

    def assert_backend_amount_from_pod(self, server_ip, amount, pod,
                                       server_port=None,
                                       protocol='TCP',
                                       namespace_name='default'):
        def req_tcp():
            ip = server_ip
            if ipaddress.ip_address(six.text_type(ip)).version == 6:
                ip = '[%s]' % ip
            url = "http://{}".format(ip)
            status_prefix = '\nkuryr-tempest-plugin-curl-http_code:"'
            cmd = ['/usr/bin/curl', '-Ss', '-w',
                   status_prefix + '%{http_code}"\n', url]
            stdout, stderr = self.exec_command_in_pod(pod, cmd,
                                                      namespace=namespace_name,
                                                      stderr=True)
            # check if the curl command succeeded
            if stderr:
                LOG.error('Failed to curl the service at {}. '
                          'Err: {}'.format(url, stderr))
                time.sleep(10)
                return
            try:
                delimiter = stdout.rfind(status_prefix)
                if delimiter < 0:
                    LOG.error('Curl output not found in stdout "%s"', stdout)
                    time.sleep(5)
                    return
                content = stdout[:delimiter]
                status_code = int(stdout[delimiter + len(status_prefix):-2])
                self.assertEqual(requests.codes.OK, status_code,
                                 'Non-successful request to {}'.format(url))
            except Exception as e:
                LOG.info("Failed to parse curl response:%s from pod, "
                         "Exception:%s.", stdout, e)
                raise e
            time.sleep(1)
            return content

        def req_udp():
            cmd = "/bin/printf hello|/bin/nc -w 5 -u {} {}".format(
                server_ip, server_port)
            pod_cmd = ["/bin/sh", "-c", cmd]
            stdout, stderr = self.exec_command_in_pod(pod, pod_cmd,
                                                      namespace=namespace_name,
                                                      stderr=True)
            if stderr:
                LOG.error('Failed to reach service at {}:{} '
                          'Err: {}'.format(server_ip, server_port, stderr))
                time.sleep(10)
                return
            return stdout

        def pred(tester, responses):
            if protocol == 'TCP':
                unique_resps = set(resp for resp in responses if resp)
            else:
                unique_resps = set(resp for resp in responses if resp
                                   != '')
            tester.assertEqual(amount, len(unique_resps),
                               'Incorrect amount of unique backends. '
                               'Got {}'.format(unique_resps))

        if protocol == 'TCP':
            req = req_tcp
        elif protocol == "UDP":
            self.assertIsNotNone(server_port, "server_port must be "
                                              "provided for UDP protocol")
            req = req_udp
        else:
            LOG.info("Unsupported protocol %s, returning", protocol)
            return
        self._run_and_assert(req, pred)

    def _run_and_assert(self, fn, predicate, retry_repetitions=100):
        resps = [fn() for _ in range(retry_repetitions)]
        predicate(self, resps)

    @classmethod
    def verify_lbaas_endpoints_configured(cls, ep_name, pod_num,
                                          namespace='default'):
        if CONF.kuryr_kubernetes.kuryrloadbalancers:
            cls._verify_klb_crd(
                ep_name, poll_interval=5, namespace=namespace,
                pod_num=pod_num)
        else:
            cls._verify_endpoints_annotation(
                ep_name=ep_name, ann_string=K8S_ANNOTATION_LBAAS_STATE,
                poll_interval=5, namespace=namespace, pod_num=pod_num)

    @classmethod
    def _verify_klb_crd(cls, name, poll_interval=1, namespace='default',
                        timeout_period=consts.LB_TIMEOUT, pod_num=None):
        start = time.time()
        klb_crd_has_status = False
        while time.time() - start < timeout_period:
            time.sleep(poll_interval)
            try:
                klb_crd = cls.get_kuryr_loadbalancer_crds(
                    name, namespace)
            except kubernetes.client.rest.ApiException:
                continue
            if (klb_crd.get('status') and
                    klb_crd['status'].get('members')):
                members_num = len(klb_crd['status'].get('members'))
                if pod_num and pod_num != members_num:
                    LOG.info("members num(%d) != pod_num(%d)",
                             members_num, pod_num)
                    continue
                klb_crd_has_status = True
                break
        if not klb_crd_has_status:
            msg = "Timed out waiting for klb crd %s creation" % name
            raise lib_exc.TimeoutException(msg)

    @classmethod
    def _verify_endpoints_annotation(cls, ep_name, ann_string,
                                     poll_interval=1, namespace='default',
                                     pod_num=None,
                                     timeout_period=consts.LB_TIMEOUT):
        LOG.info("Look for %s string in ep=%s annotation ",
                 ann_string, ep_name)

        start = time.time()
        annotation_success = False
        # wait until endpoint annotation created
        while time.time() - start < timeout_period:
            time.sleep(poll_interval)
            ep = cls.k8s_client.CoreV1Api().read_namespaced_endpoints(
                ep_name, namespace)
            annotations = ep.metadata.annotations
            try:
                annotation = json.loads(annotations[ann_string])
                # NOTE(yboaron): In some cases (depends on pod
                # creation time) K8S-Endpoints will be created in two steps.
                # The first step will be the creation of EP with a single pod,
                # and the next step will be updating EP with the second pod.
                # To handle this case properly, we need to verify not just
                # Kuryr controller annotates LBaaS state In EP but that Kuryr
                # controller annotates all members(pods).
                if (ann_string == K8S_ANNOTATION_LBAAS_STATE and
                        pod_num is not None):
                    members_num = len(annotation.get('versioned_object.data')
                                      .get('members'))
                    if pod_num != members_num:
                        LOG.info("Found %s string in ep=%s annotation but "
                                 "members num(%d) != pod_num(%d)",
                                 ann_string, ep_name, members_num, pod_num)
                        continue
                LOG.info("Found %s string in ep=%s annotation ",
                         ann_string, ep_name)
                annotation_success = True
                break
            except KeyError:
                LOG.info("Waiting till %s will appear "
                         "in ep=%s annotation ", ann_string, ep_name)
                continue
        if not annotation_success:
            msg = "Timed out waiting for %s in ep=%s annotation to appear" % (
                    ann_string, ep_name)
            raise lib_exc.TimeoutException(msg)

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
        while retry_attempts != 0:
            time.sleep(time_between_attempts)
            for controller_pod in self.get_controller_pod_names():
                self.assertEqual("Running", self.get_pod_status(
                    controller_pod,
                    CONF.kuryr_kubernetes.kube_system_namespace),
                    'Kuryr controller is not in the %s state' % status
                )
            retry_attempts -= 1

    @classmethod
    def create_route(cls, name, hostname, target_svc, namespace='default'):
        route_manifest = {
            'apiVersion': 'route.openshift.io/v1',
            'kind': 'Route',
            'metadata':
                {
                    'name': name,
                },
            'spec':
                {
                    'host': hostname,
                    'to':
                        {
                            'kind': 'Service',
                            'name': target_svc
                        }
                }
        }

        cls.k8s_client.CustomObjectsApi().create_namespaced_custom_object(
            OS_ROUTES_API, OS_ROUTES_VERSION, namespace, OS_ROUTES_PLURAL,
            route_manifest)

        LOG.info("Route=%s created, wait for kuryr-annotation", name)
        cls.wait_kuryr_annotation(
            group=OS_ROUTES_API, version=OS_ROUTES_VERSION,
            plural=OS_ROUTES_PLURAL,
            annotation='openstack.org/kuryr-route-state', timeout_period=110,
            name=name)
        LOG.info("Found %s string in Route=%s annotation ",
                 'openstack.org/kuryr-route-state', name)

    @classmethod
    def verify_route_endpoints_configured(cls, ep_name, namespace='default'):
        cls._verify_endpoints_annotation(
            ep_name=ep_name, ann_string=K8S_ANNOTATION_LBAAS_RT_STATE,
            poll_interval=3)

    @classmethod
    def delete_route(cls, name, namespace='default'):
        body = cls.k8s_client.V1DeleteOptions()
        try:
            cls.k8s_client.CustomObjectsApi().delete_namespaced_custom_object(
                OS_ROUTES_API, OS_ROUTES_VERSION, namespace, OS_ROUTES_PLURAL,
                name, body)
        except kubernetes.client.rest.ApiException as e:
            if e.status == 404:
                return
            raise

        # FIXME(yboaron): Use other method (instead of constant delay)
        # to verify that route was deleted
        time.sleep(KURYR_ROUTE_DEL_VERIFY_TIMEOUT)

    def verify_route_http(self, router_fip, hostname, amount,
                          should_succeed=True):
        LOG.info("Trying to curl the route, Router_FIP=%s, hostname=%s, "
                 "should_succeed=%s", router_fip, hostname, should_succeed)

        def req():
            if should_succeed:
                # FIXME(yboaron): From some reason for route use case,
                # sometimes only one of service's pods is responding to CURL
                # although all members and L7 policy were created at Octavia.
                # so as workaround - I added a constant delay
                time.sleep(1)

            resp = requests.get('http://{}'.format(router_fip),
                                headers={'Host': hostname})
            return resp.status_code, resp.content

        def pred(tester, responses):
            contents = []
            for resp in responses:
                status_code, content = resp
                if should_succeed:
                    contents.append(content)
                else:
                    tester.assertEqual(requests.codes.SERVICE_UNAVAILABLE,
                                       status_code)
            if should_succeed:
                unique_resps = set(contents)
                tester.assertEqual(amount, len(unique_resps),
                                   'Incorrect amount of unique backends. '
                                   'Got {}'.format(unique_resps))

        self._run_and_assert(req, pred)

    def create_and_ping_pod(self):
        name, pod = self.create_pod()
        self.addCleanup(self.delete_pod, name)
        ip = self.get_pod_ip(name)
        self.assertIsNotNone(ip)
        self.assertTrue(self.ping_ip_address(ip))
        return pod

    def update_config_map_ini_section(
            self, name, conf_to_update, section,
            namespace=CONF.kuryr_kubernetes.kube_system_namespace, **kwargs):
        # TODO(gcheresh): Check what happens if two tests try to update
        # the config map simultaneously.

        # update the config map ini part with the new values
        conf_map = self.k8s_client.CoreV1Api().read_namespaced_config_map(
            namespace=namespace, name=name)
        data_to_update = conf_map.data[conf_to_update]
        conf_parser = six.moves.configparser.ConfigParser()
        conf_parser.readfp(six.moves.StringIO(data_to_update))
        for key, value in kwargs.items():
            conf_parser.set(section, str(key), str(value))
        # TODO(gcheresh): Create a function that checks all empty string values
        # At the moment only api_root has such a value ('')
        conf_parser.set('kubernetes', 'api_root', '""')
        str_obj = six.moves.StringIO()
        conf_parser.write(str_obj)
        updated_string = str_obj.getvalue()
        conf_map.data[conf_to_update] = updated_string
        self.k8s_client.CoreV1Api().replace_namespaced_config_map(
            namespace=namespace, name=name, body=conf_map)

    @classmethod
    def get_config_map_ini_value(
            cls, name, conf_for_get, section, keys,
            namespace=CONF.kuryr_kubernetes.kube_system_namespace):
        # get the config map ini values according to the provided keys
        port_pool_dict = dict()
        conf_map = cls.k8s_client.CoreV1Api().read_namespaced_config_map(
            namespace=namespace, name=name)
        conf_parser = six.moves.configparser.ConfigParser()
        conf_parser.readfp(six.moves.StringIO(conf_map.data.get(conf_for_get)))
        for key in keys:
            try:
                port_pool_dict[key] = conf_parser.get(section, key)
            except six.moves.configparser.NoOptionError:
                port_pool_dict[key] = ''

        return port_pool_dict

    def restart_kuryr_controller(self):
        system_namespace = CONF.kuryr_kubernetes.kube_system_namespace
        for kuryr_pod_name in self.get_controller_pod_names():
            self.delete_pod(
                pod_name=kuryr_pod_name,
                body={"kind": "DeleteOptions",
                      "apiVersion": "v1",
                      "gracePeriodSeconds": 0},
                namespace=system_namespace)

            # make sure the kuryr pod was deleted
            self.wait_for_pod_status(
                kuryr_pod_name,
                namespace=system_namespace)

        # Check that new kuryr-controller is up and running
        for kuryr_pod_name in self.get_controller_pod_names():
            self.wait_for_pod_status(
                kuryr_pod_name,
                namespace=system_namespace,
                pod_status='Running',
                retries=120)

            # Wait until kuryr-controller pools are reloaded, i.e.,
            # kuryr-controller is ready
            res = test_utils.call_until_true(
                self.get_pod_readiness, 30, 1, kuryr_pod_name,
                namespace=system_namespace, container_name='controller')
            self.assertTrue(res, 'Timed out waiting for '
                                 'kuryr-controller to reload pools.')

    def update_config_map_ini_section_and_restart(
            self, name, conf_to_update, section,
            namespace=CONF.kuryr_kubernetes.kube_system_namespace, **kwargs):
        self.update_config_map_ini_section(
            name, conf_to_update, section,
            namespace, **kwargs)
        self.restart_kuryr_controller()

    def create_two_pods_affinity_setup(self, labels, affinity=None):

        """Setup of two pods

           Create a pod with one label and a second pod
           with an affinity parameter. For example, to
           make sure the second pod will land on the same
           node as the first one.
       """

        pod_name_list = []
        pod1_name, pod1 = self.create_pod(labels=labels)
        pod2_name, pod2 = self.create_pod(affinity=affinity)
        self.addCleanup(self.delete_pod, pod1_name)
        self.addCleanup(self.delete_pod, pod2_name)
        pod_name_list.extend((pod1_name, pod2_name))
        return pod_name_list

    def check_service_internal_connectivity(self, service_port='80',
                                            protocol='TCP',
                                            namespace='default',
                                            cleanup=True):
        # FIXME(itzikb): Use the clusterIP to
        # check service status as there are some issues with the FIPs
        # and OVN gates
        clusterip_svc_ip = self.get_service_ip(self.service_name,
                                               spec_type='ClusterIP',
                                               namespace=namespace)
        pod_name, pod = self.create_pod(namespace=namespace)
        if cleanup:
            self.addClassResourceCleanup(self.delete_pod, pod_name,
                                         namespace=namespace)
        self.assert_backend_amount_from_pod(
            clusterip_svc_ip,
            self.pod_num,
            pod_name,
            service_port,
            protocol,
            namespace_name=namespace)
