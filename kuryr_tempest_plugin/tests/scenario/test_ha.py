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

import datetime
import json
import threading
import time
import uuid

import kubernetes
from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from kuryr_tempest_plugin.tests.scenario import base
from kuryr_tempest_plugin.tests.scenario import consts

LOG = logging.getLogger(__name__)
CONF = config.CONF
TIMEOUT = 120


class TestHighAvailabilityScenario(base.BaseKuryrScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestHighAvailabilityScenario, cls).skip_checks()
        if not (CONF.kuryr_kubernetes.ap_ha and
                CONF.kuryr_kubernetes.containerized):
            raise cls.skipException("kuryr-controller A/P HA must be enabled "
                                    "and kuryr-kubernetes must run in "
                                    "containerized mode.")

    def get_kuryr_leader_annotation(self):
        try:
            endpoint = self.k8s_client.CoreV1Api().read_namespaced_endpoints(
                consts.HA_ENDPOINT_NAME,
                CONF.kuryr_kubernetes.kube_system_namespace)
            annotation = endpoint.metadata.annotations[
                'control-plane.alpha.kubernetes.io/leader']
            return json.loads(annotation)
        except kubernetes.client.rest.ApiException:
            return None

    def wait_for_deployment_scale(self, desired_replicas,
                                  desired_state='Running'):
        def has_scaled():
            pods = self.k8s_client.CoreV1Api().list_namespaced_pod(
                CONF.kuryr_kubernetes.kube_system_namespace,
                label_selector='name=kuryr-controller')

            return (len(pods.items) == desired_replicas and
                    all([pod.status.phase == desired_state
                         for pod in pods.items]))

        self.assertTrue(test_utils.call_until_true(has_scaled, TIMEOUT, 5),
                        'Timed out waiting for deployment to scale')

    def scale_controller_deployment(self, replicas):
        self.k8s_client.AppsV1Api().patch_namespaced_deployment(
            'kuryr-controller', CONF.kuryr_kubernetes.kube_system_namespace,
            {'spec': {'replicas': replicas}})
        self.wait_for_deployment_scale(replicas)

    @decorators.idempotent_id('3f09e7d1-0897-46b1-ba9d-ea4116523025')
    def test_scale_up_controller(self):
        controller_deployment = (
            self.k8s_client.AppsV1Api().read_namespaced_deployment(
                CONF.kuryr_kubernetes.controller_deployment_name,
                CONF.kuryr_kubernetes.kube_system_namespace))

        # On cleanup scale to original number of replicas
        self.addCleanup(self.scale_controller_deployment,
                        controller_deployment.spec.replicas)

        # Scale to just a single replica
        self.scale_controller_deployment(1)

        # Create a pod and check connectivity
        self.create_and_ping_pod()

        # Get current leader annotation
        annotation = self.get_kuryr_leader_annotation()
        self.assertIsNotNone(annotation)
        transitions = annotation['leaderTransitions']

        # Scale the controller up and wait until it starts
        self.scale_controller_deployment(2)

        # Check if leader haven't switched
        annotation = self.get_kuryr_leader_annotation()
        self.assertEqual(transitions, annotation['leaderTransitions'])

        # Create another pod and check connectivity
        self.create_and_ping_pod()

    @decorators.idempotent_id('afe75fa5-e9ca-4f7d-bc16-8f1dd7884eea')
    def test_scale_down_controller(self):
        controller_deployment = (
            self.k8s_client.AppsV1Api().read_namespaced_deployment(
                CONF.kuryr_kubernetes.controller_deployment_name,
                CONF.kuryr_kubernetes.kube_system_namespace))

        # On cleanup scale to original number of replicas
        self.addCleanup(self.scale_controller_deployment,
                        controller_deployment.spec.replicas)

        # Scale to 2 replicas
        self.scale_controller_deployment(2)

        # Create a pod and check connectivity
        self.create_and_ping_pod()

        # Scale the controller down and wait until it stops
        self.scale_controller_deployment(1)

        # Create another pod and check connectivity
        self.create_and_ping_pod()

    @decorators.idempotent_id('3b218c11-c77b-40a8-ba09-5dd5ae0f8ae3')
    def test_auto_fencing(self):
        controller_deployment = (
            self.k8s_client.AppsV1Api().read_namespaced_deployment(
                CONF.kuryr_kubernetes.controller_deployment_name,
                CONF.kuryr_kubernetes.kube_system_namespace))

        # On cleanup scale to original number of replicas
        self.addCleanup(self.scale_controller_deployment,
                        controller_deployment.spec.replicas)

        # Scale to 2 replicas
        self.scale_controller_deployment(2)

        # Create a pod and check connectivity
        self.create_and_ping_pod()

        def hostile_takeover():
            """Malform endpoint annotation to takeover the leadership

            This method runs for 3 minutes and for that time it malforms the
            endpoint annotation to simulate another kuryr-controller taking
            over the leadership. This should make other kuryr-controllers to
            step down and stop processing any events for those 3 minutes.
            """
            timeout = datetime.datetime.utcnow() + datetime.timedelta(
                minutes=3)
            fake_name = str(uuid.uuid4())
            while datetime.datetime.utcnow() < timeout:
                current = datetime.datetime.utcnow()
                renew = current + datetime.timedelta(seconds=5)
                malformed = {
                    "holderIdentity": fake_name,
                    "leaseDurationSeconds": 5,
                    "acquireTime": current.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "renewTime": renew.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "leaderTransitions": 0,
                }
                self.k8s_client.CoreV1Api().patch_namespaced_endpoints(
                    consts.HA_ENDPOINT_NAME,
                    CONF.kuryr_kubernetes.kube_system_namespace,
                    {'metadata': {'annotations': {
                        'control-plane.alpha.kubernetes.io/leader':
                            json.dumps(malformed)}}})
                time.sleep(2)

        t = threading.Thread(target=hostile_takeover)
        t.start()

        # Create another pod and check that it's not getting wired.
        time.sleep(15)  # We need to wait a bit for controller to autofence.
        name, pod = self.create_pod(wait_for_status=False)

        def is_pod_running():
            pod_obj = self.k8s_client.CoreV1Api().read_namespaced_pod(
                name, 'default')

            return pod_obj.status.phase == 'Running'

        self.addCleanup(self.delete_pod, name)
        self.assertFalse(test_utils.call_until_true(is_pod_running, TIMEOUT,
                                                    5))

        # Wait 120 seconds more, malformed annotation should get cleared
        time.sleep(TIMEOUT)

        # Now pod should have the IP and be pingable
        ip = self.get_pod_ip(name)
        self.assertIsNotNone(ip)
        self.assertTrue(self.ping_ip_address(ip, ping_timeout=TIMEOUT))
