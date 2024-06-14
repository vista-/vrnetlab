# Fortinet Fortigate

Support for the Fortinet Fortigate launched by containerlab.

## Building the docker image

Add your qcow2 image to the root of this folder.
Naming format: fortios-vX.Y.Z.qcow2

`make`

The interface alias format supported on this image is `portX`, where X is the port number, and `X = 1` is reserved for the management interface.

## Running the docker image manually

If you need to run the image without using containerlab:

`make docker-run-fortigate`

## Tested versions

* Fortigate 7.0.14 KVM
