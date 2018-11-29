# install tempest plugin
function build_test_container {
    pushd "${DEST}/kuryr-tempest-plugin/test_container"

    # FIXME(dulek): Until https://github.com/containers/buildah/issues/1206 is
    #               resolved instead of podman we need to use buildah directly,
    #               hence this awful if clause.
    if [[ ${CONTAINER_ENGINE} == 'crio' ]]; then
        sudo buildah bud -t docker.io/kuryr/demo -f Dockerfile .
    else
        docker build -t kuryr/demo . -f Dockerfile
    fi
    popd
}

function install_kuryr_tempest_plugin {
    setup_dev_lib "kuryr-tempest-plugin"
}

if [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo_summary "Building kuryr/demo test container"
        build_test_container
elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        echo_summary "Installing Kuryr Tempest Plugin"
        install_kuryr_tempest_plugin
fi
