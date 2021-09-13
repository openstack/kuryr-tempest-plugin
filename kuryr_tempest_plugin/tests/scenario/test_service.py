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
import testtools
import time

from oslo_log import log as logging
from tempest import config
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestServiceScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestServiceScenario, cls).skip_checks()
        if not CONF.network_feature_enabled.floating_ips:
            raise cls.skipException("Floating ips are not available")
        if not CONF.kuryr_kubernetes.service_tests_enabled:
            raise cls.skipException("Service tests are not enabled")

    @classmethod
    def resource_setup(cls):
        super(TestServiceScenario, cls).resource_setup()
        cls.create_setup_for_service_test()

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdcfa1a7a9')
    def test_pod_service_curl(self):
        pod_name, pod = self.create_pod()
        self.addCleanup(self.delete_pod, pod_name)
        self.assert_backend_amount_from_pod(
            self.service_ip,
            self.pod_num,
            pod_name)


class TestLoadBalancerServiceScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestLoadBalancerServiceScenario, cls).skip_checks()
        if not CONF.network_feature_enabled.floating_ips:
            raise cls.skipException("Floating ips are not available")
        if not CONF.kuryr_kubernetes.service_tests_enabled:
            raise cls.skipException("Service tests are not enabled")
        if CONF.kuryr_kubernetes.ipv6:
            raise cls.skipException('FIPs are not supported with IPv6')

    @classmethod
    def resource_setup(cls):
        super(TestLoadBalancerServiceScenario, cls).resource_setup()
        cls.create_setup_for_service_test(spec_type="LoadBalancer")

    @decorators.idempotent_id('bddf5441-1244-449d-a175-b5fdcfc2a1a9')
    def test_lb_service_http(self):
        retries = 10
        self.check_service_internal_connectivity()
        LOG.info("Trying to curl the service IP %s" % self.service_ip)

        for i in range(retries):
            self.assert_backend_amount(self.service_ip, self.pod_num)
            time.sleep(30)

    # TODO(yboaron): Use multi threads for 'test_vm_service_http' test
    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdcfa1b5a9')
    def test_vm_service_http(self):
        self.check_service_internal_connectivity()
        ssh_client, fip = self.create_vm_for_connectivity_test()
        LOG.info("Trying to curl the service IP %s from VM" % self.service_ip)
        cmd = ("curl {dst_ip}".format(dst_ip=self.service_ip))

        def curl():
            return ssh_client.exec_command(cmd)
        self._run_and_assert_fn(curl)

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fdbfc1b2a7')
    @testtools.skipUnless(
        CONF.kuryr_kubernetes.containerized,
        "test_unsupported_service_type only runs on containerized setups")
    def test_unsupported_service_type(self):
        # Testing that kuryr controller didn't crash for 100 seconds since
        # creation of service with unsupported type
        self.check_service_internal_connectivity()
        self.create_setup_for_service_test(spec_type="NodePort", get_ip=False)
        self.check_controller_pod_status_for_time_period()


class TestUdpServiceScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestUdpServiceScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.service_tests_enabled:
            raise cls.skipException("Service tests are not enabled")
        if not CONF.kuryr_kubernetes.test_udp_services:
            raise cls.skipException("Service UDP tests are not enabled")

    @decorators.idempotent_id('bddf5441-1244-449d-a125-b5fda1670781')
    def test_service_udp_ping(self):
        # NOTE(ltomasbo): Using LoadBalancer type to avoid namespace isolation
        # restrictions as this test targets svc udp testing and not the
        # isolation
        self.create_setup_for_service_test(protocol="UDP", port=90,
                                           target_port=9090)
        # NOTE(ltomasbo): Ensure usage of svc clusterIP IP instead of the FIP
        # as the focus of this test is not to check FIP connectivity.
        self.check_service_internal_connectivity(service_port='90',
                                                 protocol='UDP')


class TestServiceWithoutSelectorScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestServiceWithoutSelectorScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.test_services_without_selector:
            raise cls.skipException("Service without selectors tests"
                                    " are not enabled")

    @decorators.idempotent_id('bb8cc977-c867-4766-b623-133d8495ee50')
    def test_service_without_selector(self):
        # Create a service without selector
        ns_name, ns_obj = self.create_namespace()
        self.addCleanup(self.delete_namespace, ns_name)
        self.service_without_selector_base(namespace=ns_name)

        self.check_service_internal_connectivity(namespace=ns_name)


class TestSCTPServiceScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestSCTPServiceScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.service_tests_enabled:
            raise cls.skipException("Service tests are not enabled")
        if not CONF.kuryr_kubernetes.test_sctp_services:
            raise cls.skipException("Service SCTP tests are not enabled")

    @decorators.idempotent_id('bb8cc977-c867-4766-b623-137d8395cb60')
    def test_service_sctp_ping(self):
        self.create_setup_for_service_test(
            protocol="SCTP", port=90, target_port=9090)

        self.check_service_internal_connectivity(
            service_port='90', protocol='SCTP')


class TestListenerTimeoutScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestListenerTimeoutScenario, cls).skip_checks()
        if not CONF.kuryr_kubernetes.service_tests_enabled:
            raise cls.skipException("Service tests are not enabled")
        if not CONF.kuryr_kubernetes.test_configurable_listener_timeouts:
            raise cls.skipException("Listener timeout tests are not enabled")

    @decorators.idempotent_id('ca9bd886-d776-5675-b532-228c92a4da7f')
    def test_updated_listener_timeouts(self):
        self.create_setup_for_service_test(
            service_name="kuryr-listener-demo")

        self.check_updated_listener_timeout(
            service_name="kuryr-listener-demo")


class TestDeployment(base.BaseKuryrScenarioTest):
    credentials = ['admin', 'primary', ['lb_admin', 'load-balancer_admin']]
    @classmethod
    def skip_checks(cls):
        super(TestDeployment, cls).skip_checks()
        if not CONF.kuryr_kubernetes.service_tests_enabled:
            raise cls.skipException("Service tests are not enabled")

    @classmethod
    def setup_clients(cls):
        super(TestDeployment, cls).setup_clients()
        cls.lbaas = cls.os_roles_lb_admin.load_balancer_v2.LoadbalancerClient()
        cls.member_client = cls.os_admin.load_balancer_v2.MemberClient()
        cls.pool_client = cls.os_roles_lb_admin.load_balancer_v2.PoolClient()

    def scale_deployment(self, replicas, deployment, namespace='default'):
        self.k8s_client.AppsV1Api().patch_namespaced_deployment(
            deployment, namespace,
            {'spec': {'replicas': replicas}})

    @testtools.skipUnless(
        CONF.kuryr_kubernetes.kuryrloadbalancers,
        "kuryrloadbalancers CRDs should be used to run this test")
    @decorators.idempotent_id('bbacc377-c861-4766-b123-133d8195ee50')
    def test_deployment_scale(self):
        """Deploys a deployment, rescales and check LB members

           Deploys a deployment with 3 pods and deploys a service.
           Checks the number of LB members , Scales to 5 and do the same,
           and also checks connectivity to the service. Scales to 0 and
           checks that the number LB memebers is also 0
        """
        timeout = CONF.kuryr_kubernetes.lb_build_timeout
        deployment_name, _ = self.create_deployment()
        service_name, _ = self.create_service(pod_label={"app": "demo"},
                                              spec_type='ClusterIP')
        service_ip = self.get_service_ip(service_name, spec_type='ClusterIP')
        self.addCleanup(self.delete_service, service_name)

        klb_crd_id = self.wait_for_status(timeout, 15, self.get_klb_crd_id,
                                          service_name=service_name)

        pool_query = "loadbalancer_id=%s" % klb_crd_id

        self.wait_for_status(timeout, 15, self.lbaas.show_loadbalancer,
                             klb_crd_id)
        pool = self.wait_for_status(timeout, 15, self.pool_client.list_pools,
                                    query_params=pool_query)
        pool_id = pool[0].get('id')
        self.check_lb_members(pool_id, 3)

        self.scale_deployment(5, deployment_name)
        pod_name, _ = self.create_pod()
        self.addCleanup(self.delete_pod, pod_name)
        self.assert_backend_amount_from_pod(service_ip, 5, pod_name)
        self.check_lb_members(pool_id, 5)

        self.scale_deployment(0, deployment_name)
        self.check_lb_members(pool_id, 0)
