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

port_pool_enabled = cfg.BoolOpt("port_pool_enabled",
                                default=False,
                                help="Whether or not port pool feature is "
                                     "enabled")

lb_build_timeout = cfg.IntOpt("lb_build_timeout",
                              default=900,
                              help="The max time (in seconds) it should take "
                                   "to create LB")

namespace_enabled = cfg.BoolOpt("namespace_enabled",
                                default=False,
                                help="Whether or not namespace handler and "
                                     "driver are enabled")

service_tests_enabled = cfg.BoolOpt("service_tests_enabled",
                                    default=True,
                                    help="Whether or not service tests "
                                         "will be running")

containerized = cfg.BoolOpt("containerized",
                            default=False,
                            help="Whether or not kuryr-controller and "
                                 "kuryr-cni are containerized")

kube_system_namespace = cfg.StrOpt("kube_system_namespace",
                                   default="kube-system",
                                   help="Namespace where kuryr-controllers "
                                        "and kuryr-cnis run")

run_tests_serial = cfg.BoolOpt("run_tests_serial",
                               default=False,
                               help="Whether or not test run serially or "
                                    "in parallel")

kubernetes_project_name = cfg.StrOpt("kubernetes_project_name",
                                     default="k8s",
                                     help="The OpenStack project name "
                                          "for Kubernetes")
