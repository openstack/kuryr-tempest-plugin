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
