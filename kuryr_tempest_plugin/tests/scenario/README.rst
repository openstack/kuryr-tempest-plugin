
What are these tests?
---------------------

As stated in the tempest developer guide, scenario tests are meant to be used to
test the interaction between several OpenStack services to perform a real-life
use case.

In the case of the Kuryr Tempest Plugin it also involves interaction with
Kubernetes pods, so its manager class includes handlers to its python bindings.

A developer using this manager would be able to perform, among others, CRUD
operations with pods, alongside Kuryr-K8s added funcionality.
