# Copyright 2015
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg

service_option = cfg.BoolOpt("kuryr",
                             default=True,
                             help="Whether or not kuryr is expected to be "
                                  "available")

ports_pool_batch = cfg.IntOpt("ports_pool_batch",
                              default=10,
                              help="The size of pool batch when "
                                   "KURYR_USE_PORT_POOLS is enabled")
ports_pool_max = cfg.IntOpt("ports_pool_max",
                            default=0,
                            help="Maximum number of ports when "
                                 "KURYR_USE_PORT_POOLS is enabled")
ports_pool_min = cfg.IntOpt("ports_pool_min",
                            default=5,
                            help="Minimum number of ports when "
                                 "KURYR_USE_PORT_POOLS is enabled")

kuryr_k8s_opts = [
    cfg.BoolOpt("port_pool_enabled", default=False,
                help="Whether or not port pool feature is enabled"),
    cfg.IntOpt("lb_build_timeout", default=1000,
               help="The max time (in seconds) it should take to create LB"),
    cfg.BoolOpt("namespace_enabled", default=False,
                help="Whether or not namespace handler and driver are "
                     "enabled"),
    cfg.BoolOpt("network_policy_enabled", default=False,
                help="Whether or not network policy handler and driver are "
                     "enabled"),
    cfg.BoolOpt("service_tests_enabled", default=True,
                help="Whether or not service tests will be running"),
    cfg.BoolOpt("containerized", default=False,
                help="Whether or not kuryr-controller and kuryr-cni are "
                     "containerized"),
    cfg.StrOpt("kube_system_namespace", default="kube-system",
               help="Namespace where kuryr-controllers and kuryr-cnis run"),
    cfg.BoolOpt("run_tests_serial", default=False,
                help="Whether or not test run serially or in parallel"),
    cfg.StrOpt("kubernetes_project_name", default="k8s",
               help="The OpenStack project name for Kubernetes"),
    cfg.BoolOpt("npwg_multi_vif_enabled", default=False,
                help="Whether or not NPWG multi-vif feature is enabled"),
    cfg.StrOpt("ocp_router_fip", default=None, help="OCP Router floating IP"),
    cfg.BoolOpt("kuryr_daemon_enabled", default=True, help="Whether or not "
                "kuryr-kubernetes is configured to run with kuryr-daemon"),
    cfg.BoolOpt("ap_ha", default=False,
                help='Whether or not A/P HA of kuryr-controller is enabled'),
    cfg.StrOpt("controller_deployment_name", default="kuryr-controller",
               help="Name of Kubernetes Deployment running kuryr-controller "
                    "Pods"),
    cfg.BoolOpt("test_udp_services", default=False,
                help="Whether or not service UDP tests will be running"),
    cfg.BoolOpt("test_sctp_services", default=False,
                help="Whether or not service SCTP tests will be running"),
    cfg.BoolOpt("multi_worker_setup", default=False, help="Whether or not we "
                "have a multi-worker setup"),
    cfg.BoolOpt("cloud_provider", default=False, help="Whether or not a "
                "cloud provider is set"),
    cfg.BoolOpt("validate_crd", default=False, help="Whether or not kuryr "
                "CRDs should be validated"),
    cfg.BoolOpt("kuryrloadbalancers", default=False, help="Whether or not "
                "kuryrloadbalancers CRDs are used"),
    cfg.BoolOpt("kuryrnetworks", default=False, help="Whether or not "
                "kuryrnetworks CRDs are used"),
    cfg.BoolOpt("new_kuryrnetworkpolicy_crd", default=False,
                help="Whether or not KuryrNetworkPolicy CRDs are used instead "
                     "of KuryrNetPolicy"),
    cfg.BoolOpt("configmap_modifiable", default=False, help="Whether config "
                "map can be changed"),
    cfg.StrOpt("controller_label", default="name=kuryr-controller",
               help="The label is used to identify the Kuryr controller pods"),
    cfg.BoolOpt("prepopulation_enabled", default=False,
                help="Whether prepopulation of ports is enabled"),
    cfg.BoolOpt("subnet_per_namespace", default=False,
                help="Whether there is a subnet per each namespace"),
    cfg.BoolOpt("ipv6", default=False,
                help="True if Kuryr is configured to use IPv6 subnets as pod "
                     "and service subnets."),
    cfg.BoolOpt("test_services_without_selector", default=False,
                help="Whether or not service without selector tests will be "
                "running"),
    cfg.BoolOpt("test_endpoints_object_removal", default=True,
                help="Whether to check that LB members are deleted upon "
                "endpoints object removal or not"),
    cfg.BoolOpt("test_configurable_listener_timeouts", default=False,
                help="Whether or not listener timeout values are "
                "configurable"),
    cfg.IntOpt("lb_members_change_timeout", default=1200,
               help="The max time (in seconds) it should take to adjust the "
               " number LB members"),
    cfg.BoolOpt("enable_reconciliation", default=False,
                help="Whether or not reconciliation is enabled"),
    cfg.BoolOpt("enable_listener_reconciliation", default=False,
                help="Whether or not listener reconciliation is enabled"),
    cfg.IntOpt("lb_reconcile_timeout", default=600,
               help="The max time (in seconds) it should take for LB "
               "reconciliation. It doesn't include the LB build time."),
    cfg.BoolOpt("trigger_namespace_upon_pod", default=False,
                help="Whether or not Namespace should be handled upon Pod "
                "creation"),
    cfg.BoolOpt("annotation_project_driver", default=False,
                help="Whether or not annotation project tests will be "
                     "running"),
    cfg.BoolOpt("set_pod_security_context", default=False,
                help="Whether or not to set security context for Kuryr demo "
                     "pods"),

]
