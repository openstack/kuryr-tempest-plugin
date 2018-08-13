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
from kuryr_tempest_plugin.tests.scenario import base
from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators


LOG = logging.getLogger(__name__)
CONF = config.CONF

FIRST_ROUTE_NAME = 'firstroute'
FIRST_ROUTE_HOST_NAME = 'www.first.com'
SECOND_ROUTE_NAME = 'secondroute'
SECOND_ROUTE_HOST_NAME = 'www.second.com'


class TestOcpRouteScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestOcpRouteScenario, cls).skip_checks()
        if CONF.kuryr_kubernetes.ocp_router_fip is None:
            raise cls.skipException(
                "OCP router fip should be specified to run this tests.")

    @decorators.idempotent_id('bddf0001-1244-449d-a125-b5fdcfa1a7a9')
    def test_create_route_after_service(self):
        self.create_setup_for_service_test()
        self.addCleanup(self.delete_route, FIRST_ROUTE_NAME)
        self.create_route(FIRST_ROUTE_NAME, FIRST_ROUTE_HOST_NAME,
                          self.service_name)

        self.verify_route_endpoints_configured(self.service_name)
        self.verify_route_http(CONF.kuryr_kubernetes.ocp_router_fip,
                               FIRST_ROUTE_HOST_NAME,
                               self.pod_num)
        self.delete_route(FIRST_ROUTE_NAME)
        self.verify_route_http(CONF.kuryr_kubernetes.ocp_router_fip,
                               FIRST_ROUTE_HOST_NAME,
                               self.pod_num,
                               should_succeed=False)

    @decorators.idempotent_id('bddf0002-1244-449d-a125-b5fdcfa1a7a9')
    def test_two_routes_same_service(self):
        self.create_setup_for_service_test()
        self.addCleanup(self.delete_route, FIRST_ROUTE_NAME)
        self.create_route(FIRST_ROUTE_NAME, FIRST_ROUTE_HOST_NAME,
                          self.service_name)
        self.addCleanup(self.delete_route, SECOND_ROUTE_NAME)
        self.create_route(SECOND_ROUTE_NAME, SECOND_ROUTE_HOST_NAME,
                          self.service_name)
        self.verify_route_endpoints_configured(self.service_name)

        self.verify_route_http(CONF.kuryr_kubernetes.ocp_router_fip,
                               FIRST_ROUTE_HOST_NAME,
                               self.pod_num)
        self.verify_route_http(CONF.kuryr_kubernetes.ocp_router_fip,
                               SECOND_ROUTE_HOST_NAME,
                               self.pod_num)
        self.delete_route(FIRST_ROUTE_NAME)
        self.verify_route_http(CONF.kuryr_kubernetes.ocp_router_fip,
                               SECOND_ROUTE_HOST_NAME,
                               self.pod_num)
        self.verify_route_http(CONF.kuryr_kubernetes.ocp_router_fip,
                               FIRST_ROUTE_HOST_NAME,
                               self.pod_num,
                               should_succeed=False)

    @decorators.idempotent_id('bddf0003-1244-449d-a125-b5fdcfa1a7a9')
    def test_create_route_before_service(self):
        service_name = data_utils.rand_name(prefix='kuryr-service')
        self.addCleanup(self.delete_route, FIRST_ROUTE_NAME)
        self.create_route(FIRST_ROUTE_NAME, FIRST_ROUTE_HOST_NAME,
                          service_name)
        self.create_setup_for_service_test(service_name=service_name)
        self.verify_route_endpoints_configured(service_name)
        self.verify_route_http(CONF.kuryr_kubernetes.ocp_router_fip,
                               FIRST_ROUTE_HOST_NAME,
                               self.pod_num)
