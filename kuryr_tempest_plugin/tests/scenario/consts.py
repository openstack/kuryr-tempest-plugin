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
POD_OUTPUT = 'HELLO! I AM ALIVE!!!'
HA_ENDPOINT_NAME = 'kuryr-controller'
POD_AFFINITY = {'requiredDuringSchedulingIgnoredDuringExecution': [
    {'labelSelector': {'matchExpressions': [
        {'operator': 'In', 'values': ['demo'], 'key': 'type'}]},
        'topologyKey': 'kubernetes.io/hostname'}]}
TIME_TO_APPLY_SGS = 30
POD_STATUS_RETRIES = 240
POD_CHECK_TIMEOUT = 240
POD_CHECK_SLEEP_TIME = 5
NP_CHECK_SLEEP_TIME = 10
NS_TIMEOUT = 600
LB_TIMEOUT = 1200
LB_RECONCILE_TIMEOUT = 600
REPETITIONS_PER_BACKEND = 10
KURYR_RESOURCE_CHECK_TIMEOUT = 300
KURYR_PORT_CRD_PLURAL = 'kuryrports'
KURYR_LOAD_BALANCER_CRD_PLURAL = 'kuryrloadbalancers'
KURYR_NETWORK_POLICY_CRD_PLURAL = 'kuryrnetworkpolicies'
K8s_ANNOTATION_PROJECT = 'openstack.org/kuryr-project'
LOADBALANCER = 'loadbalancer'
LISTENER = 'listeners'
